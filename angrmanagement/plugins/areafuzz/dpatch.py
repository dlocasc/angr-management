#!/usr/bin/env python3

import sys
import argparse
import logging
import shutil
import angr

log = logging.getLogger(__name__)


def build_whitelist(target_addr, cfg, mode, symbols):
	worklist = []
	visited = set()
	whitelist = set()
	

	if mode == 'block':
		# In block mode we keep an unpatched path to the target address
		# and no further
		for node in cfg.model.get_all_nodes(target_addr, is_syscall=False):
			worklist.append(node)
			whitelist.add(node.addr)
	elif mode == 'function':
		# In function mode we extend the unpatched path to reach the end of
		# the function
		# There's a possibility of multiple return paths for the function,
		# so we have to discover them all and add them to the worklist
		for block in cfg.kb.functions[target_addr].endpoints:
			for node in cfg.model.get_all_nodes(block.addr):
				worklist.append(node)
				visited.add(node.block_id)
				whitelist.add(node.addr)
	else:
		raise Exception('Invalid whitelist mode')

	while len(worklist) > 0:
		node = worklist.pop(0)
		parents = node.predecessors
		for parent in parents:
			if parent.block_id not in visited:
				visited.add(parent.block_id)
				whitelist.add(parent.addr)
				worklist.append(parent)
	return whitelist


def patch(file, whitelist, cfg, proj, symbols):
	for node in cfg.graph.nodes():
		if node.addr not in whitelist:
			section = proj.loader.main_object.find_section_containing(node.addr)
			if section and section.name == '.text':
				addr = node.addr - proj.loader.min_addr
				log.debug('patching 0x%x (size %d)%s', addr, node.size, ' - {}+{:x}'.format(symbols[node.function_address], node.addr - node.function_address) if node.function_address in symbols else '')
				file.seek(addr)
				file.write(b'\xcc') # int3
				#file.write(b'\x48\x31\xc0\xb0\x3c\x0f\x05') # exit primitive (broken)


def run_patcher(filename, patched_name, target, mode):
	proj = angr.Project(filename, auto_load_libs=False)
	# the target can either be a symbol name or an address
	target_addr = proj.loader.find_symbol(target)
	if target_addr:
		target_addr = target_addr.rebased_addr
	else:
		target_addr = proj.loader.min_addr + int(target, 0)


	#cfg = proj.analyses.CFGFast()
	cfg = proj.analyses.CFGEmulated()

	# Possible solution to cycles
	# Don't think this is necessary though
	# due to CFGEmulated context-sensitivity
	#cfg.remove_cycles()

	# build symbol lookup table for comprehensive logging
	symbol_table = {s.rebased_addr: s.name for s in proj.loader.symbols}
	whitelist = build_whitelist(target_addr, cfg, mode, symbol_table)
	log.debug('Whitelist: {%s}', ', '.join([hex(i) for i in whitelist]))

	# create copy of binary to patch
	shutil.copy(proj.filename, patched_name)

	# needs to be r+b, just wb makes seeking around the binary not work
	with open(patched_name, 'r+b') as patched:
		patch(patched, whitelist, cfg, proj, symbol_table)


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-l', '--loglevel', help='Level of logs to output to stdout')
	parser.add_argument('-b', '--block', action='store_true', help='use block mode')
	parser.add_argument('-f', '--function', action='store_true', help='use function mode')
	parser.add_argument('-o', '--out', help='where to place patched binary, defaults to <binary name>.patched')
	parser.add_argument('target', help='target address or symbol')
	parser.add_argument('binary', help='the binary file to patch')
	args = parser.parse_args()
	if args.loglevel:
		log.setLevel(args.loglevel)
	logging.getLogger('cle.loader').setLevel('ERROR')
	if args.block:
		mode = 'block'
	elif args.function:
		mode = 'function'
	else:
		print('Please specify either -b or -f', file=sys.stderr)
		parser.print_usage()
		sys.exit(1)
	out_filename = args.out if args.out else '{}.patched'.format(args.binary)
	run_patcher(args.binary, out_filename, args.target, mode)


if __name__ == '__main__':
	main()
