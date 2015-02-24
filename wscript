# vi: ft=python

APPNAME = 'hype'
VERSION = '0.1'

def options(opt):
	opt.load('compiler_c')

	opt.add_option('--sanitize', action='store', default=None,
	               help='enable specified sanotizer (address, thread, ...)')

def configure(cfg):
	def my_check_cc(ctx, dep, **kw_ext):
		kw_ext['uselib_store'] = dep
		if ctx.check_cc(**kw_ext):
			ctx.env.deps.append(dep)

	def my_check_cfg(ctx, dep, **kw_ext):
		kw_ext['args'] = '--cflags --libs'
		kw_ext['uselib_store'] = dep
		if ctx.check_cfg(**kw_ext):
			ctx.env.deps.append(dep)

	def my_check_lua(ctx, lua_versions):
		for lua in lua_versions:
			if ctx.check_cfg(package=lua, args='--cflags --libs', \
			                 uselib_store=lua, mandatory=False):
				ctx.env.deps.append(lua)
				return

		ctx.fatal('Could not find Lua')

	def my_check_os(ctx):
		ctx.env.deps.append("os-{0}".format(ctx.env.DEST_OS))

	cfg.load('compiler_c')

	cfg.env.CFLAGS   += [ '-Wall', '-pedantic', '-g', '-std=gnu99' ]
	cfg.env.CPPFLAGS += [ '-D_GNU_SOURCE' ]

	cfg.env.deps = []

	# OS
	my_check_os(cfg)

	# system libs
	my_check_cc(cfg, 'm',       lib='m',       mandatory=True)
	my_check_cc(cfg, 'pthread', lib='pthread', mandatory=True)
	my_check_cc(cfg, 'resolv',  lib='resolv',  mandatory=True)
	my_check_cc(cfg, 'rt',      lib='rt',      mandatory=True)

	# Lua
	my_check_lua(cfg, ['luajit', 'lua5.2', 'lua5.1'])

	# urcu
	my_check_cc(cfg, 'urcu', lib=['urcu', 'urcu-common'],
	            header_name='urcu/wfcqueue.h', mandatory=True)

	# pcap
	my_check_cc(cfg, 'pcap', lib='pcap',
	            header_name='pcap.h', mandatory=True)

	if cfg.options.sanitize == 'address':
		cfg.env.CFLAGS  += [ '-fsanitize=address' ]
		cfg.env.LINKFLAGS += [ '-fsanitize=address' ]

		cfg.msg('Checking for sanitizer', 'address')

	if cfg.options.sanitize == 'thread':
		cfg.env.CFLAGS  += [ '-fsanitize=thread', '-fPIC' ]
		cfg.env.LINKFLAGS += [ '-fsanitize=thread', '-pie' ]

		cfg.msg('Checking for sanitizer', 'thread')

	if cfg.options.sanitize == 'undefined':
		cfg.env.CFLAGS  += [ '-fsanitize=undefined' ]
		cfg.env.LINKFLAGS += [ '-fsanitize=undefined' ]

		cfg.msg('Checking for sanitizer', 'thread')

	if cfg.options.sanitize == 'leak':
		cfg.env.CFLAGS  += [ '-fsanitize=leak' ]
		cfg.env.LINKFLAGS += [ '-fsanitize=leak' ]

		cfg.msg('Checking for sanitizer', 'leak')

def build(bld):
	includes = [
		'deps/lua-compat-5.2',
		'deps/lua-pack',
		'deps/siphash',
		'deps/ta',
		'deps/ut',
		'src',
	]

	sources = [
		# sources
		'src/bucket.c',
		'src/hype.c',
		'src/netif_pcap.c',
		'src/pkt.c',
		'src/pkt_arp.c',
		'src/pkt_chksum.c',
		'src/pkt_cookie.c',
		'src/pkt_eth.c',
		'src/pkt_icmp.c',
		'src/pkt_ip4.c',
		'src/pkt_raw.c',
		'src/pkt_tcp.c',
		'src/pkt_udp.c',
		'src/printf.c',
		'src/ranges.c',
		'src/resolv.c',
		'src/resolv_linux.c',
		'src/routes_linux.c',
		'src/script.c',
		'src/util.c',

		# Lua 5.2 compat
		'deps/lua-compat-5.2/compat-5.2.c',

		# Lua pack lib
		'deps/lua-pack/lpack.c',

		# siphash
		'deps/siphash/siphash24.c',
	]

	bld.env.append_value('INCLUDES', includes)

	bld(
		target       = 'hype',
		features     = 'c cprogram',
		source       = sources,
		use          = bld.env.deps,
		install_path = bld.env.BINDIR
	)
