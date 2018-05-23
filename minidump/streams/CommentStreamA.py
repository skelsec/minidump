#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
class CommentStreamA:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def parse(dir, buff):
		csa = CommentStreamA()
		buff.seek(dir.Location.Rva)
		csa.data = buff.read(dir.Location.DataSize).decode()
		return csa
	
	def __str__(self):
		return 'CommentA: %s' % self.data