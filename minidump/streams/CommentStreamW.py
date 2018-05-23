#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
class CommentStreamW:
	def __init__(self):
		self.data = None
	
	@staticmethod
	def parse(dir, buff):
		csa = CommentStreamW()
		buff.seek(dir.Location.Rva)
		csa.data = buff.read(dir.Location.DataSize).decode('utf-16-le')
		return csa
		
	def __str__(self):
		return 'CommentW: %s' % self.data