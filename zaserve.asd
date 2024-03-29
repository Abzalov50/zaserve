;;; ASD file contributed by james anderson <james.anderson@setf.de>
;;; Updated for zaserve/zacl fork by Dave Cooper <dave+gendl@genworks.com>
(in-package :cl-user)


#+allegro
(defpackage #:acl-reader (:export #:cl-file))

#+allegro
(defclass acl-reader:cl-file (asdf:cl-source-file)
  ((type :initform "cl")))

#+allegro
(asdf:defsystem
 :zaserve
 :author "John K. Foderaro"
 :licence "LLGPL"
 :description "Trivial shim to load built-in aserve when running on Allegro CL" 
 :components ((acl-reader:cl-file "require-builtin-aserve")))



#-allegro
(defun check-platform-compatibilty ()
  (unless (or (member :ccl *features*)
	      (member :sbcl *features*))
    (error "

SORRY:
=====

This version of AllegroServe, is not currently supported on ~a. Please
consider contributing, or requesting, a port of zacl for ~a.

For the legacy PortableAllegroserve, please try system name `paserve'.


"
	   (lisp-implementation-type) (lisp-implementation-type))))

#-(or zacl allegro)
(defpackage :zacl-reader (:export #:cl-file))

#-allegro
(asdf:defsystem
 :zaserve
 :author "John K. Foderaro"
 :licence "LLGPL"
 :description "Lightly modified fork of original AllegroServe for portability" 
 :depends-on (:zacl :cl+ssl :salza2 :ironclad :cl-ppcre)
 :defsystem-depends-on (:zacl)
 :version "1.3.65"
 :name "AllegroServe"
 :components
 ;; this list is in load.cl as well... keep in sync
 ((:module "htmlgen" :components ((zacl-reader:cl-file "htmlgen")
                                  (:static-file "ChangeLog")))  
  (zacl-reader:cl-file "packages")
  (zacl-reader:cl-file "macs")
  (zacl-reader:cl-file "queue")
  (zacl-reader:cl-file "main")
  (zacl-reader:cl-file "headers")
   (zacl-reader:cl-file "parse")
  (zacl-reader:cl-file "decode")
  (zacl-reader:cl-file "publish")
  (zacl-reader:cl-file "authorize")
  (zacl-reader:cl-file "log" )
  (zacl-reader:cl-file "client")
  (zacl-reader:cl-file "proxy")
  (zacl-reader:cl-file "cgi")
  (zacl-reader:cl-file "chunker")
  (zacl-reader:cl-file "secure-cookie")
  
  (:module "webactions"
	   :components ((zacl-reader:cl-file "websession")
			(zacl-reader:cl-file "webact")			
			(zacl-reader:cl-file "clpage")
			(:module "clpcode"
				 :components
				 ((zacl-reader:cl-file "clp")	  
				  (zacl-reader:cl-file "http")
				  (zacl-reader:cl-file "time")
				  (zacl-reader:cl-file "wa"))
				 :depends-on ("clpage")
				  ))			
			)
  #+include-playback (zacl-reader:cl-file "playback")

  (:static-file "README.md")
  (:static-file "ChangeLog")
  (:static-file "license-lgpl.txt")
  (:static-file "LICENSE")
  (:static-file "load"))
 :perform (asdf:load-op :before (op zaserve)
			(check-platform-compatibilty))
 ;:serial t
 )



