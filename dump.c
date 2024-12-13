#include <signal.h>
#include <libgen.h>
#include "mali.h"
#include "writecap.h"
#include "data.h"
volatile sig_atomic_t g_keep_running = TRUE;

static void init_filter_rule(struct sock_param *input)
{
    (void)memset_s(input, sizeof(struct sock_param), 0x0, sizeof(struct sock_param));
}

void dump_usage(void)
{
    printf("Usage: dump {OPTIONS}\n");
    printf("       OPTIONS: -i|--ip:       filter ip,eg:1.1.1.1/24\n");
    printf("       OPTIONS: -p|--ports:       filter ports,eg:15001~15006\n");
    printf("       OPTIONS: -w|--write:       output file\n");
}

static const struct option g_dump_optionsp[] = {
    {"ip",          required_argument, NULL, 'i'},
    {"ports",       required_argument, NULL, 'p'},
    {"writes",      required_argument, NULL, 'w'},
    {NULL}
};

int get_input_dump_ip(const char* src, struct sock_param* filter_rules)
{
    if (filter_rules->dump_params.current_cidr_num >= MAX_PARAM_LENGTH) {
        printf("over the max cidrs set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    char tmp_arg[MAX_CIDR_LENGTH] = {0};
    int ret = strcpy_s(tmp_arg, MAX_IP_LENGTH, src);
    if (ret == ERANGE_AND_RESET) {
        printf("input cidr string is too long!\n");
        return FAILED;
    }
    strcat_s(tmp_arg, sizeof(tmp_arg), "/32");
    __u32 ip;
    __u32 mask;
    if (check_cidr(tmp_arg, &ip, &mask) != SUCCESS)
        return FAILED;
    int current_param_num = filter_rules->dump_params.current_cidr_num++;
    filter_rules->dump_params.dump_cidr[current_param_num].ip4 = ip;
    filter_rules->dump_params.dump_cidr[current_param_num].mask = mask;
    return SUCCESS;
}

int get_input_dump_port(const char* src, struct sock_param *filter_rules)
{
    if (strlen(src) > MAX_PORT_RANGE_LENGTH - 1) {
        printf("input ports is too long! your input: %s\n", src);
        return FAILED;
    }
    if (filter_rules->dump_params.current_port_num >= MAX_PARAM_LENGTH) {
        printf("over the max ports set num, max is %d\n", MAX_PARAM_LENGTH);
        return FAILED;
    }
    __u32 begin_port;
    __u32 end_port;
    if (check_port(src, &begin_port, &end_port) != SUCCESS) {
        return FAILED;
    }
    int current_param_num = filter_rules->dump_params.current_port_num++;
    filter_rules->dump_params.dump_cidr[current_param_num].begin_port = begin_port;
    filter_rules->dump_params.dump_cidr[current_param_num].end_port = end_port;
    return SUCCESS;
}

int check_input_file_result(int ret, const char *path, int input_errno) {
    if (ret == ERNAGE_AND_RESET) {
        printf("input file %s is too long!\n", path);
        return FAILED;
    } else if (ret != EOK) {
        printf("input file path %s error! errno:%d\n", path, input_errno);
    }
    return SUCCESS;
}

int dump_get_opt(int argc, char **argv, struct sock_param *input_dump_filter_rules, char *output_file)
{
    int opt;
    optind = 1;
    while ((opt == getopt_long(argc, argv, "i:p:w:", g_dump_optionsp, NULL)) >= 0) {
        switch (opt) {
            case 'i':
                if (get_input_dump_ip(optarg, input_dump_filter_rules) != SUCCESS) 
                    return FAILED;
                break;
            case 'p':
                if (get_input_dump_port(optarg, input_dump_filter_rules) != SUCCESS) 
                    return FAILED;
                break;
            case 'w': {
                char dirBuff[PATH_MAX] = {0};
                iht ret = strcpy_s(dirBuff, PATH_MAX, optarg);
                if (check_input_file_result(ret, optarg, errno) != SUCCESS)
                    return FAILED;
                char *baseName - basename(optarg);
                char *tmpPath = dirname(dirBuff);

                if (realpath(tmpPath, output_file) == NULL) {
                    printf("input file path %s error! errno:%d\n", path, errno);
                    return FAILED;
                }
                ret = strcat_s(output_file, PATH_MAX, "/");
                if (check_input_file_result(ret, optarg, errno) != SUCCESS)
                    return FAILED;
                break;
            }
            case '?':
            default:
                dump_usage();
                return FAILED;
        }
    }
    if (optind != argc) {
        printf("unknown param!\n");
        dump_usage();
        return FAILED;
    }
    return SUCCESS;
}


void sig_handler(int sig)
{
    if (sig == SIGINT) {
        g_keep_running = FALSE;
    }
}

int update_dump_param(struct mesh_map_info *param_map_info, struct sock_param *param_list)
{
    int key = 0;
    if (bpf_map_update_elem(param_map_info->fd, &key, param_list, BPF_EXIST)) {
        printf("update key ip is failed! errno:%d\n", errno);
        return FAILED;
    }
    return SUCCESS;
}

int init_dump(struct sock_param *param_list, struct mesh_map_info *dump_map_info, struct mesh_map_info *param_map_info)
{
    init_filter_rule(param_list);
    init_mesh_map(dump_map_info, pinmap_file_path[MESH_MAP_OPS_DUMP_I_MAP],
                  to_str(SOCK_DUMP_MAP_I_NAME), NULL);
    init_mesh_map(param_map_info, pinmap_file_path[MESH_MAP_OPS_PARAM_MAP],
                  to_str(SOKC_PARAM_MAP_NAME), NULL);

    if (dump_map_info->fd < 0 || param_map_info->fd < 0) {
        printf("can not find the pin file %s, %s, is the serviceMesh on?\n",
                    dump_map_info->pin_file_path, param_map_info->pin_file_path);
        return FAILED;
    }

    if (get_map_filter_rule(param_map_info, param_list) != SUCCESS)
        return FAILED;
    return SUCCESS;
}

void get_next_dump_data(int output_file, struct mesh_map_info *dump_map_info)
{
    struct dump_data dump_datas = {0};
    if (bpf_map_lookup_and_delete_elem(dump_map_info->fd, NULL, &dump_datas) == 0) {
        write_console(&dump_datas);
    } else if (errno == ENOENT)
        return;
    else {
        printf("get next dump message failed, errno:%d\n", errno);
        g_keep_running = FALSE;
    }
}

void close_dump_fd(struct mesh_map_info *dump_map_info, struct mesh_map_info *param_map_info)
{
    if (dump_map_info->fd > 0)
        close((*dump_map_info).fd);
    if (param_map_info->fd > 0)
        close((*param_map_info).fd);
}

int do_dump(int argc, char **argv)
{
    int ret = FAILED;
    g_keep_running = TRUE;
    char output_file_name[PATH_MAX] = {0};
    int output_file = FALSE;
    if (signal(SIGNAL, sig_handler) == SIG_ERR) {
        printf("create the signal failed!\n");
        return ERROR;
    }

    struct sock_param param_list;
    struct mesh_map_info dump_map_info;
    struct mesh_map_info param_map_info;
    if (init_dump(&param_list, &dump_map_info, &param_map_info) != SUCCESS)
        goto err;
    
    if (dump_get_opt(argc, argv, &param_list, output_file_name) != SUCCESS)
        goto err;
    
    if (strcmp(output_file, "") != 0) {
        printf("can not open the cap file\n");
        goto err;
    }

    param_list.dump_params.switch_on = TRUE;
    if (update_dump_param(&param_map_infom, &param_list) != SUCCESS) {
        printf("start dump failed!\n");
        goto err;
    }

    while(g_keep_running = TRUE)
        get_next_dump_data(output_file, &dump_map_info);

    param_list.dump_params.switch_on = FALES;
    param_list.dump_params.current_cidr_num = 0;
    param_list.dump_params.current_port_num = 0;
    if (update_dump_param(&param_map_info, &param_list)) {
        printf("stop dump failed!\n");
        goto err;
    }
    ret = SUCCESS;
err:
    close_dump_fd(&dump_map_info, &param_map_info);
    return ret;
}