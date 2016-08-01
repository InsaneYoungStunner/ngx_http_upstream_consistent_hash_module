#include<ngx_http_upstream_consistent_hash_module.h>
//启动upstream 服务时用来初始化
static ngx_int_t ngx_http_upstream_consistent_hash_init(ngx_conf_t *cf,ngx_http_upstream_srv_conf_t *us){
  uint32_t    step;
  ngx_http_upstream_server_t  *server;
  u_char       hash_data[HASH_DATA_LENGTH];
  ngx_http_upstream_consistent_hash_buckets  *buckets;
  ngx_http_upstream_consistent_hash_ring_t   *ring;
  ngx_uint_t                    i,j,k,n,points = 0;
  for(i = 0; i < HASH_DATA_LENGTH; i++)
    hash_data[i] = 0;
  step = (uint32_t)(0xffffffff / BUCKET_NUMBER);

  buckets = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_consistent_hash_buckets));
  us->peer.init = ngx_http_upstream_consistent_hash_init_peer;

  if(!us->servers){
    return NGX_ERROR;
  }
  server = us->servers->elts;

  for(n = 0,i = 0; i < us->servers->nelts; i++){
    n += server[i].naddrs;  //backend地址数
    points += server[i].weight * server[i].naddrs * POINTS_UNIT;
  }

  ring = ngx_pcalloc(cf->pool,sizeof(ngx_http_upstream_consistent_hash_buckets));
  ring->nodes = ngx_pcalloc(cf->pool,sizeof(ngx_http_upstream_consistent_hash_node_t) * points);

  for(i = 0; i < us->servers->nelts; i++){
    for(j = 0; j < server[i].naddrs;j++){
      for(k = 0; k < (POINTS_UNIT * server[i].weight); k++){
        ngx_snprintf(hash_data, HASH_DATA_LENGTH, "%V-%ui%Z",&server[i].addrs[j].name,k);
        ring->nodes[ring->nnodes].sockaddr = server[i].addrs[j].sockaddr;
        ring->nodes[ring->nnodes].name = server[i].addrs[j].name;
        ring->nodes[ring->nnodes].socklen = server[i].addrs[j].socklen;
        ring->nodes[ring->nnodes].name.data[server[i].addrs[j].name.len] = 0;
        ring->nodes[ring->nnodes].point = ngx_crc32_long(hash_data,ngx_strlen(hash_data));
        ring->nnodes++;
      }
    }
  }

  //排序
  qsort(ring->nodes,ring->nnodes,sizeof(ngx_http_upstream_consistent_hash_node_t),(const void*)ngx_http_upstream_consistent_hash_compare_ring_nodes);

  for(i = 0; i < BUCKET_NUMBER; i++){
    buckets->buckets[i] = ngx_http_upstream_consistent_hash_find_node(ring, i * step);
  }

  buckets->ring = ring;
  us->peer.data = buckets;

  return NGX_OK;
}
// for qsort
static ngx_int_t ngx_http_upstream_consistent_hash_compare_ring_nodes(
          const ngx_http_upstream_consistent_hash_node_t* node1,
          const ngx_http_upstream_consistent_hash_node_t* node2)
{
    if(node1.point > node2.point)
        return 1;
    else if(node1.point < node2.point)
        return -1;
    else
        return 0;
}

//找到匹配的，二分查找
static ngx_http_upstream_consistent_hash_node_t* ngx_http_upstream_consistent_hash_find_node(
     ngx_http_upstream_consistent_hash_ring_t* ring, uint32_t point)
{
    ngx_int_t     mid,small,big;
    mid = 0;small = 0;big = ring->nnodes - 1;
  for(;;){
    if(point <= ring->nodes[small].point || point > ring->nodes[big].point)
        return &ring->nodes[small];

    mid = small + (big - small) / 2;

    //找到最左边第一个匹配的
    if(point <= ring.nodes[mid].point && point > (mid == 0 ? ring.nodes[0].point : ring.nodes[mid - 1].point))
        return &ring.nodes[mid];

    if(ring.nodes[mid].point < point)
        small = mid + 1;
    else
        big = mid - 1;
  }
}
//发现http和server配置项时调用
//其中http是在Preconfiguration后调用
static void* ngx_http_upstream_consistent_hash_create_srv_conf(ngx_conf_t cf){
  ngx_http_upstream_consistent_hash_srv_conf_t    *ushscf;
  ushscf = ngx_pcalloc(cf->pool,sizeof(ngx_http_upstream_consistent_hash_srv_conf_t));
  if(ushscf == NULL)
      return NULL;
  return ushscf;
}
/*
typedef struct {
0040     ngx_conf_t                 *cf;
0041     ngx_str_t                  *source;
0042
0043     ngx_array_t               **flushes;
0044     ngx_array_t               **lengths;
0045     ngx_array_t               **values;
0046
0047     ngx_uint_t                  variables;
0048     ngx_uint_t                  ncaptures;
0049     ngx_uint_t                  captures_mask;
0050     ngx_uint_t                  size;
0051
0052     void                       *main;
0053
0054     unsigned                    compile_args:1;
0055     unsigned                    complete_lengths:1;
0056     unsigned                    complete_values:1;
0057     unsigned                    zero:1;
0058     unsigned                    conf_prefix:1;
0059     unsigned                    root_prefix:1;
0060
0061     unsigned                    dup_capture:1;
0062     unsigned                    args:1;
0063 } ngx_http_script_compile_t;
*/

//解析配置项的时候调用
static char* ngx_http_upstream_consistent_hash(ngx_conf_t *cf, ngx_command_t *cmd,void *conf){
  ngx_str_t                                     *value;
  ngx_http_script_compile_t                      sc;
  ngx_http_upstream_srv_conf_t                  *uscf;
  ngx_http_upstream_consistent_hash_srv_conf_t  *uchscf;

  uscf = ngx_http_conf_get_module_srv_conf(cf,ngx_http_upstream_module);
  value = cf->args->elts;
  uchscf = ngx_http_conf_upstream_srv_conf(uscf,ngx_http_upstream_consistent_hash_module);

  ngx_memzero(&sc,sizeof(ngx_http_script_compile_t));

  sc.cf = cf;
  // &value[1]就是consistent_hash后面配置的字符串，含有变量
  sc.source = &value[1];
 /*
  * 这里需要交代的是，nginx这套”运行时处理机“在处理结果的处理上是分长度和内容
  * 两部分的，也就是说，获得变量实际值对应长度和内容的处理子(也就是处理函数)，分别
  * 保存在lengths和values中。
  */
  sc.lengths = uchscf.lengths;
  sc.values = uchscf.values;
  /* 这两个值是作为一次compile的结束标记，在lengths和values的最后添加一个空处理子，即NULL指针。
	* 在运行时处理时，即处理lengths和values的时候，碰到NULL，这次处理过程就宣告结束 */
  sc.complete_values = 1;
  sc.complete_lengths = 1;

  /*配置解析变量时需要调用的函数，储存在&uchscf->values中，以及一些准备设置。
	*对变量的实际解析在ngx_http_script_run中进行，因为有些变量只有在用到的时候才能得到相应的值，比如$remote_addr 这种动态参数
	*/
  if(ngx_http_script_compile(&sc) != NGX_OK)
      return NGX_CONF_ERROR;

  uscf->peer.init_upstream = ngx_http_upstream_consistent_hash_init;
  uscf->flags = NGX_HTTP_UPSTREAM_WEIGHT | NGX_HTTP_UPSTREAM_CREATE;

  return NGX_CONF_OK;
}


//向upstream服务器发送请求时初始化peer
//对于一个请求将要对backend服务器发起peer请求时进行initialize，对peer进行初始化
static ngx_int_t
ngx_http_upstream_consistent_hash_init_peer(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *uscf)
{
  ngx_int_t                                        key_for_hash;
  ngx_http_upstream_consistent_hash_srv_conf_t    *uchscf;
  ngx_http_upstream_consistent_hash_peer_data_t   *uchpd;

  uchscf = ngx_http_conf_upstream_srv_conf(uscf,ngx_http_upstream_consistent_hash_module);
  if(uchscf == NULL)
      return NGX_ERROR;

  uchpd = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_consistent_hash_peer_data_t));
  if(uchpd == NULL)
      return NGX_ERROR;

  r->upstream->peer.data = uchpd->peers;//ngx_http_upstream_consistent_hash_buckets    *peers;
  uchpd->peers = uscf->peer.data;

  //解析consistent_hash后面的值到 key_for_hash中，可能为变量，比如$remote_addr，根据客服端来hash，起到负载均衡和ip_hash的共存效果
  if(ngx_http_script_run(r, &key_for_hash, uchscf->lengths->elts, 0,
              uchscf->values->elts) == NULL)
        return NGX_ERROR;

  //针对解析的值（key_for_hash)用hash函数得到hash-key
  uchpd = ngx_crc32_long(key_for_hash.data,key_for_hash.len);
  r->upstream->peer.data = uchpd;
  r->upsrream->peer.get = ngx_http_upstream_consistent_hash_get_peer;
  r->upstream->peer.free = ngx_http_upstream_consistent_hash_free_peer;

  return NGX_OK;
}

/*
0037 struct ngx_peer_connection_s {
0038     ngx_connection_t                *connection;
0039
0040     struct sockaddr                 *sockaddr;
0041     socklen_t                        socklen;
0042     ngx_str_t                       *name;
0043
0044     ngx_uint_t                       tries;
0045     ngx_msec_t                       start_time;
0046
0047     ngx_event_get_peer_pt            get;
0048     ngx_event_free_peer_pt           free;
0049     void                            *data;
0050
0051 #if (NGX_SSL)
0052     ngx_event_set_peer_session_pt    set_session;
0053     ngx_event_save_peer_session_pt   save_session;
0054 #endif
0055
0056     ngx_addr_t                      *local;
0057
0058     int                              type;
0059     int                              rcvbuf;
0060
0061     ngx_log_t                       *log;
0062
0063     unsigned                         cached:1;
0064 #if (NGX_HAVE_TRANSPARENT_PROXY)
0065     unsigned                         transparent:1;
0066 #endif
0067
0069     unsigned                         log_error:2;
0070 };
0071 */

//获得连接的方法，如果使用长连接构成的连接池，则必须实现
static ngx_int_t ngx_http_upstream_consistent_hash_get_peer(ngx_peer_connection_t* pc,void* data){
  ngx_http_upstream_consistent_hash_peer_data_t    *uchpd;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                 "consistent hash point: %ui", uchpd->point);
  pc->cached = 1;
  pc->connection = NULL;

  //一个bucket对应一个server，但一个server可能对应多个bucket。根据uchpd的hash-key得到对应的bucket也就是server，
  //然后将对应的backend服务器参数赋予pc这个主动连接的peer-connection数据结构
  pc->sockaddr = uchpd->peers->buckets[uchpd->point % BUCKET_NUMBER]->sockaddr;
  pc->socklen = uchpd->peers->buckets[uchpd->point % BUCKET_NUMBER]->socklen;
  pc->name = uchpd->peers->buckets[uchpd->point % BUCKET_NUMBER]->name;

  return NGX_OK;
}

static void ngx_http_upstream_consistent_hash_free_peer(
          ngx_peer_connection_t *pc,void *data,ngx_uint32_t)
{
  pc->tries = 0;
}
