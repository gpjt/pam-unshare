## pam-unshare

A [PAM module](http://www.linux-pam.org/) that switches into a PID namespace,
with /proc correctly mounted.

Just a sketch at the moment -- it seems to work fine, but logs too much and
probably contains errors.

Suggestions/pull requests welcome!

Inspiration drawn with thanks from Jameson Little's [simple-pam](https://github.com/beatgammit/simple-pam) and from Ed
Schmollinger's [pam-chroot](https://sourceforge.net/projects/pam-chroot/).
