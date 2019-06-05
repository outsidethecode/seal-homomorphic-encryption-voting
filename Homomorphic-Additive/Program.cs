using System;
using Microsoft.Research.SEAL;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;

namespace Homomorphic_Additive
{
    class Program
    {
        static void Main(string[] args)
        {
            int votersCount = 5;
            ulong[] votes = createSampleVotes(votersCount);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 2048;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 2048);
            parms.PlainModulus = new SmallModulus(1 << 8);

            SEALContext context = SEALContext.Create(parms);

            IntegerEncoder encoder = new IntegerEncoder(context);

            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;

            Encryptor encryptor = new Encryptor(context, publicKey);

            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            int value1 = 5;
            Plaintext plain1 = encoder.Encode(value1);
            Console.WriteLine($"Encoded {value1} as polynomial {plain1.ToString()} (plain1)");

            int value2 = -7;
            Plaintext plain2 = encoder.Encode(value2);
            Console.WriteLine($"Encoded {value2} as polynomial {plain2.ToString()} (plain2)");

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Console.Write("Encrypting plain1: ");
            encryptor.Encrypt(plain1, encrypted1);
            Console.WriteLine("Done (encrypted1)");

            Console.Write("Encrypting plain2: ");
            encryptor.Encrypt(plain2, encrypted2);
            Console.WriteLine("Done (encrypted2)");

            Console.WriteLine($"Noise budget in encrypted1: {decryptor.InvariantNoiseBudget(encrypted1)} bits");
            Console.WriteLine($"Noise budget in encrypted2: {decryptor.InvariantNoiseBudget(encrypted2)} bits");

            evaluator.NegateInplace(encrypted1);
            Console.WriteLine($"Noise budget in -encrypted1: {decryptor.InvariantNoiseBudget(encrypted1)} bits");

            evaluator.AddInplace(encrypted1, encrypted2);

            Console.WriteLine($"Noise budget in -encrypted1 + encrypted2: {decryptor.InvariantNoiseBudget(encrypted1)} bits");
            evaluator.MultiplyInplace(encrypted1, encrypted2);
            Console.WriteLine($"Noise budget in (-encrypted1 + encrypted2) * encrypted2: {decryptor.InvariantNoiseBudget(encrypted1)} bits");
            Plaintext plainResult = new Plaintext();
            Console.Write("Decrypting result: ");
            decryptor.Decrypt(encrypted1, plainResult);
            Console.WriteLine("Done");

            Console.WriteLine($"Plaintext polynomial: {plainResult.ToString()}");

            Console.WriteLine($"Decoded integer: {encoder.DecodeInt32(plainResult)}");
        }

        static ulong[] createSampleVotes(int size)
        {
            Random random = new Random();
            ulong[] votes = new ulong[size];
            for (int i = 0; i < size; i++)
            {
                votes[i] = (ulong)random.Next(1, 3);
            }
            return votes;
        }

    }
}
