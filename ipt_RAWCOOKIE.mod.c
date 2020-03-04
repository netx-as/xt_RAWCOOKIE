#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x28950ef1, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xe2efd2d4, __VMLINUX_SYMBOL_STR(xt_unregister_target) },
	{ 0x4b6bdb2d, __VMLINUX_SYMBOL_STR(xt_register_target) },
	{ 0x195c9f2c, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xcf6b0abb, __VMLINUX_SYMBOL_STR(ip_local_out_sk) },
	{ 0x8841d39b, __VMLINUX_SYMBOL_STR(synproxy_build_options) },
	{ 0x52a41251, __VMLINUX_SYMBOL_STR(__cookie_v4_init_sequence) },
	{ 0x2ac95217, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xaf3f0d3e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0xb42e336a, __VMLINUX_SYMBOL_STR(synproxy_options_size) },
	{ 0x6e450479, __VMLINUX_SYMBOL_STR(synproxy_parse_options) },
	{ 0x8ef01d8b, __VMLINUX_SYMBOL_STR(skb_copy_bits) },
	{ 0xb2e32ccd, __VMLINUX_SYMBOL_STR(nf_ip_checksum) },
	{ 0xef7db50c, __VMLINUX_SYMBOL_STR(synproxy_net_id) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xc435ce0a, __VMLINUX_SYMBOL_STR(dst_release) },
	{ 0x826789e8, __VMLINUX_SYMBOL_STR(pskb_expand_head) },
	{ 0x9cdcbf5f, __VMLINUX_SYMBOL_STR(inet_addr_type) },
	{ 0xb11f4a48, __VMLINUX_SYMBOL_STR(ip_route_output_flow) },
	{ 0x78f9b710, __VMLINUX_SYMBOL_STR(nf_ct_l3proto_try_module_get) },
	{ 0xb602c57e, __VMLINUX_SYMBOL_STR(nf_ct_l3proto_module_put) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=nf_synproxy_core,nf_conntrack";


MODULE_INFO(srcversion, "B0DDF68DF074A6D13289206");
MODULE_INFO(rhelversion, "7.6");
#ifdef RETPOLINE
	MODULE_INFO(retpoline, "Y");
#endif
#ifdef CONFIG_MPROFILE_KERNEL
	MODULE_INFO(mprofile, "Y");
#endif
