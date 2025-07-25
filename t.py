from pwn import *

context.log_level = 'debug'
p = remote("localhost", 26555)

p.interactive()
