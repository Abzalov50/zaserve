The AllegroServe Webserver
====================================================

Original : https://github.com/gendl/aserve


*** Support for SSL on SBCL, using package CL+SSL
The file "main.cl" has been modified to insert an `accept-hook', in the function `start', that allows the creation of an SSL stream, from a normal HTTP stream.
Strangely, passing this hook as argument to the function `start' does not work as intended.

*** Bug fixes: 
-The function `start-lisp-thread-server' creates more than one `accept-thread' with the same name, and these threads are not all destructed at shutdown

TODO
-Support for response body compression on SBCL, using package SALZA2
