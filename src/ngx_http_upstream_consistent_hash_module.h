#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

#define HASH_DATA_LENGTH 28
#define BUCKET_NUMBER 1024
#define POINTS_UNIT 200

struct ngx_http_upstream_consistent_hash_srv_conf_s{
    ngx_array_t*  values;
    ngx_array_t*  lengths;
};

typedef ngx_http_upstream_consistent_hash_srv_conf_s ngx_http_upstream_consistent_hash_srv_conf_t;

struct ngx_http_upstream_consistent_node_s{
    ngx_str_t         name;
    struct sockaddr   *sockaddr;
    socklen_t         socklen;
    uint32_t          point;

};

typedef ngx_http_upstream_consistent_hash_node_s ngx_http_upstream_consistent_hash_node_t;

struct ngx_http_upstream_consistent_hash_ring_s{
    //ring整体起点
    ngx_http_upstream_consistent_hash_node_t    *nodes;
    ngx_uint32_t                                 nnodes;
    ngx_int_t                                    numpoints;
};

typedef ngx_http_upstream_consistent_hash_ring_s ngx_http_upstream_consistent_hash_ring_t;

struct ngx_http_upstream_consistent_hash_buckets_s{
    ngx_http_upstream_consistent_hash_node_t      *buckets[BUCKET_NUMBER];
    ngx_http_upstream_consistent_hash_ring_t      *ring;
};

typedef ngx_http_upstream_consistent_hash_buckets_s ngx_http_upstream_consistent_hash_buckets_t;

struct ngx_http_upstream_consistent_hash_peer_data_s{
    ngx_http_upstream_consistent_hash_buckets_t   *peers;
    ngx_uint32_t                                   tries;
    ngx_event_get_peer_pt                          get_rr_peer;
}

static char* ngx_http_upstream_consistent_hash(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static void* ngx_http_upstream_consistent_hash_create_srv_conf(ngx_conf_t*);
/* typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);*/
static ngx_int_t ngx_http_upstream_consistent_hash_init(ngx_conf_t*, ngx_http_upstream_srv_conf_t*);
/*typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
         ngx_http_upstream_srv_conf_t *us); */
static ngx_int_t ngx_http_upstream_consistent_hash_init_peer(ngx_http_request_t *r,
         ngx_http_upstream_srv_conf_t* us);

static ngx_int_t ngx_http_upstream_consistent_hash_get_peer(ngx_peer_connection_t* ,void*);
static void ngx_http_upstream_consistent_hash_free_peer(ngx_peer_connection_t*, void*, ngx_uint_t);
static int ngx_http_upstream_consistent_hash_compare_ring_nodes(const ngx_http_upstream_consistent_hash_node_t*,
         const ngx_http_upstream_consistent_hash_node_t*);
static ngx_http_upstream_consistent_hash_node_t*
              ngx_http_upstream_consistent_hash_find_node(ngx_http_upstream_consistent_hash_ring_t*, uint32_t);
static ngx_command_t ngx_http_upstream_consistent_hash_commands[] = {
    {
      ngx_string("consistent_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_consistent_hash,
      //ngx_uint_t conf
      0,
      //ngx_uint_t offset
      0,
      //post pointer
      NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_upstream_consistent_hash_module_ctx = {
     NULL,
     NULL,

     NULL,
     NULL,

     ngx_http_upstream_consistent_hash_create_srv_conf,
     NULL,

     NULL,
     NULL
};

ngx_module_t ngx_http_consistent_hash_module = {
  NGX_MODULE_V1,
  &ngx_http_upstream_consistent_hash_module_ctx,
  ngx_http_upstream_consistent_hash_commands,
  NGX_HTTP_MODULE,
  NULL,
  NULL,

  NULL,
  NULL,

  NULL,
  NULL,

  NULL,

  NGX_MODULE_V1_PADDING
};
