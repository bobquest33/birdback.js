all: uglify

uglify: 
		cp license.txt build/birdback.js 
		uglifyjs vendor/jsbn/jsbn.js vendor/jsbn/prng4.js vendor/jsbn/rng.js vendor/jsbn/sha1.js vendor/jsbn/rsa.js vendor/jsbn/base64.js vendor/asn1.js pkcs-oaep.js birdback.js >> build/birdback.js
test:
		nosetests tests/runner.py	
