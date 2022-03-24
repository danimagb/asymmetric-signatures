using System.Security.Cryptography;
using System.Text;

var privateKey = @"MIIEpAIBAAKCAQEAl5zRqpKzOBpB3GXT12kBBukz+lgNjAPxG3O6iP8M5SikfFxdemNBS/i+Puj+r9azzgTeb7CR+G6ZrCoI1cZ34h7fVm0zTug3M3DGUsT7TpbhZgdUsh0gInBME41Sr46NGYUg1yBpfC/wEf9N9V4JNNV43qOYq9THWR3VF5xZ+H7OpAjyZ42jSNnIJNIEoih7QSX5SJCYfVDO+UApvzax2TOn54mbWCmOK0QsOKSZjujEuj2kmc+0nxs1z/X07GIM5MjQ6LkuFvPzxta5F68Het9QdKKfkTdv65CxwO/en8I8rN4B9e8+TLtzCsNiRgyFgZ3UtMm1/v2tmtHJx0ZMVQIDAQABAoIBAEu7KX/qh1sewoc01fxjlv+8vRnvodSuo2DzDdogjHBrPL5h5M+dhKBOP7ls6Mssk+P0yqc/q6pMlLZKyN7/pCJvCWBCa76ef/RSAL6XZnB7LVupjcTqh4KsVVPu476Nli2JMj5DEm3WBDT5Mhe+QRsDBr0vOrOaNXluTWLd1pMo/313Q+2wBiBucOZ7dLozrX+bHrQ/vyBEvot3vkb+DjGGJYqzSquRnzvITqLY7DO2zpLinZ4IlREFm+9ARbHFnr9+aoj+cUIaP5pyZWitkW/bk72GAeyBobsTTPoM056TWr1eQoMs9vTjUYEP0xE/hmevtAklYVDWilu+LBSozoECgYEAxCOCVJLllSL5Y9OVxvt6TGwDtmows/13RiK0DoM+8Zavt4I9sWDEKEsSjaKbPOG4Qqu8HWognGbCBAzjgezFk4xTjktArSIq9hGDID/yIefSY8dWH5NXO/URXxYprlXyqbjrQY/ihyMrGJZzvGcrMAh79tjLVml8dgGuVVoZt8cCgYEAxeJxlci9K8xg4cbA6GYNNzCn56jVmy19NCDyIUAAF/lI84RiBMBfDq+WYvDQ8HjdaLTIt/qVa5n8QJ0QiKDuLLsTliOIEFeKqrcwED9w3lZjuy65XE/tmtbNVhDsHm6KzyGMJvzTdJU2t0LAmdm63Ix6fJH5CVOBASb12WC/swMCgYBwO5VvSaNfhGTKT59r/iiMJF63eeomhEpE8sSvbUCOQ1iHHFqq7iEwoUybiUllPBAQ7m41Mq44cMBiSvHAPbkM5gZF7R+0MlH8/iZXROALsLh96emJJemL4H6xN2BgZsP1hF/x4yCPjXsylZziWPKoiKJOrN0ltDTI3cthAa6nrwKBgQCeeZPnlcTR/7KS/f5d3+Szj1bYcuDmjo6Xoc7ni/7HNFAVHa72CS3XcA1rHVrnSpRel3GrzZW+f6qCAIdONDuqPQQZmEkOdV1LDLwENxpoJR1nuaqe4C/0chQt2g2O7Y5jBYXdb1rVIe6Y42+lhrZcjHBHtQuRSXul9ZKsTQwZCwKBgQCPB710sayjfYKZbbio6C69WJufKwUAvv/M/TGL1wQvV9S6KpWm6EtrtK3iRxXVJGv/UieFFjbf4MyGMDfkXt/mHukxc08deAvZs9fwNOUj1e1n537C3DJsrEVkcpBEQKA09beALXh/7eC6w+7yx4EJWAx+MaUreI7FY/KVanQmkg==";
var publicKey = @"MIIBCgKCAQEAl5zRqpKzOBpB3GXT12kBBukz+lgNjAPxG3O6iP8M5SikfFxdemNBS/i+Puj+r9azzgTeb7CR+G6ZrCoI1cZ34h7fVm0zTug3M3DGUsT7TpbhZgdUsh0gInBME41Sr46NGYUg1yBpfC/wEf9N9V4JNNV43qOYq9THWR3VF5xZ+H7OpAjyZ42jSNnIJNIEoih7QSX5SJCYfVDO+UApvzax2TOn54mbWCmOK0QsOKSZjujEuj2kmc+0nxs1z/X07GIM5MjQ6LkuFvPzxta5F68Het9QdKKfkTdv65CxwO/en8I8rN4B9e8+TLtzCsNiRgyFgZ3UtMm1/v2tmtHJx0ZMVQIDAQAB";

var hashAlg = "sha256";
string data = "Hello!";

Console.WriteLine("Scenario 1 - Loading keys from string..");

var serverStringKey = LoadPrivateKeyFromString(privateKey);
var clientStringKey = LoadPublicKeyFromString(publicKey);

var signatureOne = Sign(hashAlg, data, serverStringKey);
ValidateSignature(hashAlg, data, signatureOne, clientStringKey);

Console.WriteLine("Scenario 2 - Loading keys from pem files..");

var serverPemKey = LoadKeyFromPemFile("./keys/private-key.pem");
var clientPemKey = LoadKeyFromPemFile("./keys/public-key.pem");

var signatureTwo = Sign(hashAlg, data, serverPemKey);
ValidateSignature(hashAlg, data, signatureTwo, clientPemKey);


static byte[] Sign(string hashAlg, string data, RSA key) {

    var hashData = Hash(hashAlg, data);

    //Create an RSAPKCS1SignatureFormatter object and pass it the
    //RSA instance to transfer the private key.
    RSAPKCS1SignatureFormatter rsaFormatter = new RSAPKCS1SignatureFormatter(key);

    //Set the hash algorithm
    rsaFormatter.SetHashAlgorithm(hashAlg);

    //Create a signature for hashValue and assign it to
    //signedHashValue.
    return rsaFormatter.CreateSignature(hashData);
}


static void ValidateSignature(string hashAlg, string data, byte[] signature, RSA key) 
{
    var hashData = Hash(hashAlg, data);

    //Create an RSAPKCS1SignatureDeformatter object and pass it the
    //RSA instance to transfer the public key.
    RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(key);

    //Set the hash algorithm
    rsaDeformatter.SetHashAlgorithm(hashAlg);

    if (rsaDeformatter.VerifySignature(hashData, signature))
    {
        Console.WriteLine("The signature is valid.");

    }
    else
    {
        Console.WriteLine("The signature is not valid.");
    }
}

static RSA LoadKeyFromPemFile(string path) {
    var pem = File.ReadAllText(path);

    var key = RSA.Create();
    key.ImportFromPem(pem);

    return key;
}

static RSA LoadPrivateKeyFromString(string privateKey) {
    RSA key = RSA.Create();
    key.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);

    return key;
}

static RSA LoadPublicKeyFromString(string publicKey)
{
    RSA key = RSA.Create();
    key.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);

    return key;
}

static byte[] Hash(string algName, string input)
{
    using (var hashAlgorithm = HashAlgorithm.Create(algName))
    {
        if (hashAlgorithm is null)
        {
            throw new CryptographicException($"Unable to hash data using the '{algName}' algorithm");
        }

        return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
    }
}