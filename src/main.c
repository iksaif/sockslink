#include "sockslink.h"
#include "args.h"

int main(int argc, char *argv[])
{
  SocksLink sl;
  int ret;

  ret = sockslink_init(&sl);
  if (ret)
    goto exit;

  ret = parse_args(argc, argv, &sl);
  if (ret)
    goto exit;

  ret = sockslink_start(&sl);
  if (ret)
    goto exit;

  ret = sockslink_loop(&sl);

 exit:
  sockslink_stop(&sl);
  sockslink_clear(&sl);
  return ret;
}
