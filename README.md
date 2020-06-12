# crypt3 - crypt(3)-based password encryption

This program provides a straightforward command-line interface to [crypt(3)](https://www.man7.org/linux/man-pages/man3/crypt.3.html).

## Install

```
sudo apt install libssl-dev
./autogen.sh
./configure
make check
sudo make install
```

## Use

```
$ crypt3 
Enter password: 
Retype password: 
$6$DLwtdvJ.mGpVjtsd$6NKZLh/WIi9Gd2vvnYrzJ7bDCrOA2lTMasIdrzy9V//BsRDL9yC2RIxJan5eaExJkWUKleh125B22FN64PELs0
```

## Documentation

```
crypt3 --help
man crypt3
```

## Security

`crypt3` will let you specify passwords on the command line.
This isn't very secure since command line are visible in `ps`,
but it's convenient for low-value passwords.

`crypt3` makes no effort to evaluate password strength.

`crypt3` will let you use obsolete modes of crypt(3),
even though they are totally insecure.
Only use them if you're stuck with an ancient application which cannot do better.

`crypt3` exists to interwork with applications that are already committed to crypt(3).
If you're creating a new system and need to protect passwords, consult [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html).

## Licence

### crypt3

Copyright © Richard Kettewell. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [www.gnu.org/licenses](https://www.gnu.org/licenses/).

### libcrypt3

crypt3 embeds its own copy of the password-hashing code,
in order to be independent of platform C libraries
(which don't all support the same algorithms).
The code used was taken from FreeBSD.

Variously copyright ©
Dag-Erling Smørgrav,
David Burren,
Mark Murray,
Poul-Henning Kamp,
Richard Kettlewell,
The FreeBSD Project,
University of California.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the name of the author nor the names of other contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.
