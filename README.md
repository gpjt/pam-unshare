pam-unshare
===========

A [PAM module](http://www.linux-pam.org/) that switches into a PID namespace,
with /proc correctly mounted.

Just a sketch at the moment -- it seems to work fine, but logs too much and
probably contains errors.

Suggestions/pull requests welcome!


How to use it
-------------

Compile, and copy `pam_unshare.so` to `/lib/security/`.

In one of the pam config files -- say, `/etc/pam.d/su`, add a line saying this:

    session required      pam_unshare.so

This will mean that anyone who uses `su` will wind up in a separate process
namespace.  `ps` and everything in `/proc` will reflect that -- the rest of
the processes on the system will be invisible.  You can affect other tools
(say, `sshd`) by changing their respective `pam.d` config files.

NB. this is not something you'd want to leave in there for root; a TODO is
definitely make this module a do-nothing for root, and perhaps to allow you
to specify a list of users who are likewise unaffected...


How it works
------------

See [this blog post](http://www.gilesthomas.com/2016/04/pam-unshare-a-pam-module-that-switches-into-a-pid-namespace/).


Acknowledgements
----------------

Inspiration drawn from Jameson Little's [simple-pam](https://github.com/beatgammit/simple-pam) and from Ed
Schmollinger's [pam-chroot](https://sourceforge.net/projects/pam-chroot/).


License
-------

MIT-licensed, see `LICENSE.txt`.

