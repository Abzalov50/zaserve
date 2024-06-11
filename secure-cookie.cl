;; -*- mode: common-lisp; package: net.aserve -*-
#|
This code is an adaptation of the package `hunchentoot-secure-cookie' 
(https://github.com/gihnius/hunchentoot-secure-cookie)
to Allegro Serve.
I am very grateful to the author (Gihnius lyj <gihnius@gmail.com>) of that package.

Adapted by: Arnold N'GORAN <arnoldngoran@gmail.com>
|#

(in-package :net.aserve)

;; crypto configure
(let ((@secret-key-base "")
      (@encrypt-key nil)
      (@sign-key nil)
      (@encrypt-salt "encrypted cookie")
      (@sign-salt "signed cookie")
      (@random-key-p nil))
  (defun gen-key (salt)
    (ironclad:pbkdf2-hash-password
     (babel:string-to-octets @secret-key-base :encoding :utf-8)
     :salt (if @random-key-p
               (ironclad:make-random-salt 64)
               (babel:string-to-octets salt :encoding :utf-8))
     :digest 'ironclad:sha256
     :iterations 1000))

  (defun register-keys ()
    (setf @encrypt-key (gen-key @encrypt-salt))
    (setf @sign-key (gen-key @sign-salt)))

  (defun encrypt-key ()
    @encrypt-key)

  (defun sign-key ()
    @sign-key)

  (defun secure-cookie-p ()
    "Encrypt cookie if token is set"
    (and (> (length @secret-key-base) 0)
         @encrypt-key
         @sign-key
         t))

  ;; the interface to init or change the secret key token.
  (defun set-secret-key-base (key)
    "change or init the secret-key-base value(string)"
    (setq @secret-key-base key)
    (register-keys))

  (defun set-encrypt-salt (salt)
    (setf @encrypt-salt salt)
    (register-keys))

  (defun set-sign-salt (salt)
    (setf @sign-salt salt)
    (register-keys))

  (defun set-random-key-p (p)
    (setf @random-key-p (not (not p)))
    (register-keys)))
;; end crypto configure

;; generate random IV
(defun generate_iv ()
  (ironclad:make-random-salt (ironclad:block-length 'ironclad:aes))
  ;;(ironclad:make-random-salt 8)
  )

;; use AES-CBC-256 cipher default
;; return: cipher
;; key: the encrypt-key (bytes array)
(defun get-cipher (key iv)
  (ironclad:make-cipher 'ironclad:aes :key key :mode 'ironclad:cbc :initialization-vector iv))

;; base64 encode before concatenate
(defun pack-cookie (name encrypted-value)
  "name|date|value"
  (format nil "~A|~A|~A"
          (cl-base64:string-to-base64-string name)
          (get-universal-time) ; integer
          (cl-base64:usb8-array-to-base64-string encrypted-value)))

;; remove name and append mac digest => "date|value|mac"
(defun pack-signature (cookie-name pack mac-digest)
  (let ((name-len (length (cl-base64:string-to-base64-string cookie-name)))
        (mac-str (cl-base64:usb8-array-to-base64-string mac-digest)))
    (format nil "~A|~A" (subseq pack (1+ name-len)) mac-str)))

;; => "date|value|mac"
;; make sure return the right format
;; restore | by: base64-string -> string
(defun unpack-cookie (val)
  (let* ((dec (cl-base64:base64-string-to-string val))
         (list (cl-ppcre:split "\\|" dec)))
    (if (and list (eql (length list) 3))
        (values-list list)
        (values "" "" ""))))

;; name: cookie-name (string)
;; value: cookie-value (string)
;; return base64 of encrypted value of "data|value|mac"
(defun encrypt-and-encode (name value)
  (format t "~&VALUE: ~A~%" value)
  (let ((mac (ironclad:make-hmac (sign-key) 'ironclad:SHA256))
        (iv (generate_iv))
        (content (babel:string-to-octets value :encoding :utf-8 )))
    (ironclad:encrypt-in-place (get-cipher (encrypt-key) iv) content)
    (let* ((new-content (concatenate '(vector (unsigned-byte 8)) iv content)) ; include the IV
           (pack (pack-cookie name new-content)))      
      (format t "~&PACK: ~A~%" pack) 
      (ironclad:update-hmac mac (babel:string-to-octets pack :encoding :utf-8))
      (print (pack-signature name pack (ironclad:hmac-digest mac)))
      (cl-base64:string-to-base64-string (pack-signature name pack (ironclad:hmac-digest mac))))))

;; return nil if failed to decrypt/decode/hmac-verify
(defun decode-and-decrypt (name value)
  (multiple-value-bind (ts content hmac) (unpack-cookie value) ; "date|value|mac"
    (let* ((mac (ironclad:make-hmac (sign-key) 'ironclad:SHA256))
           (back-pack (format nil "~A|~A|~A"
                              (cl-base64:string-to-base64-string name)
                              ts
                              content)) ; "name|date|value"
           (back-hmac-digest (cl-base64:base64-string-to-usb8-array hmac)))
      ;; Verify hmac
      (ironclad:update-hmac mac (babel:string-to-octets back-pack :encoding :utf-8))
      ;; TODO: also check the ts (get-universal-time) format
      (when (equalp back-hmac-digest (ironclad:hmac-digest mac))
        ;; extract the iv and decrypt
        (let* ((data (cl-base64:base64-string-to-usb8-array content))
               (iv (subseq data 0 (ironclad:block-length 'ironclad:aes)))
               (val (subseq data (ironclad:block-length 'ironclad:aes))))
          (ironclad:decrypt-in-place (get-cipher (encrypt-key) iv) val)
          (babel:octets-to-string val :encoding :utf-8))))))

;; set http-only to true in SECURE COOKIE
(defun set-secure-cookie (req &key name (value "") expires (path "/") domain secure (http-only t))
  "set the secure cookie, works like `set-cookie-header' in Allegro Serve."
  (when (secure-cookie-p)
    (let ((val (handler-case (encrypt-and-encode name value)
		 (t (c)
		   (values
		    nil
		    (logmess
		     (format nil "*** WARNING: Failed to encode or encrypt cookie value! ~S" c)))))
	    ))
      (set-cookie-header req :name name :value val :expires expires
                         :path path :domain domain :secure secure :http-only http-only))))

(defun get-cookie-val (key req)
  (cdr (assoc key (get-cookie-values req) :test #'equal)))
  
(defun get-secure-cookie (name req)
  "get cookie using cookie-in then decode and decrypt, return NIL if failed."
  (let ((cookie-value (get-cookie-val name req)))
    (when (and (secure-cookie-p) cookie-value (> (length cookie-value) 0))
      (handler-case
          (decode-and-decrypt name cookie-value)
        (t (c)
	  (values nil
		  (logmess
		   (format nil "*** WARNING: Failed to decode or decrypt cookie value! ~S" c))))))))

(defun delete-secure-cookie (name req &key domain)
  (set-secure-cookie req :name name :value "" :domain domain))
