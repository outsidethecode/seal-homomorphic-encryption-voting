﻿using System;
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
            int votersCount = 10;
            int[] votes = createSampleVotes(votersCount);
            Console.WriteLine("votes=[{0}]", string.Join(", ", votes));
            Console.WriteLine("Sum of all votes = {0}", votes.Sum());

            SEALContext context = createContext();
            IntegerEncoder encoder = new IntegerEncoder(context);
            KeyGenerator keygen = new KeyGenerator(context);

            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            Ciphertext encryptedTotal = new Ciphertext();
            encryptor.Encrypt(encoder.Encode(0), encryptedTotal);

            Ciphertext encrypted = new Ciphertext();
            Console.WriteLine("-----------------------------------");
            Console.WriteLine("Encoding the vote values ... ");
            for (int i = 0; i < votes.Length; i++)
            {
                Plaintext plain = encoder.Encode(votes[i]);
                encryptor.Encrypt(plain, encrypted);
                // Console.WriteLine($"Noise budget in encrypted: {decryptor.InvariantNoiseBudget(encrypted)} bits");
                Console.WriteLine($"Encoded {votes[i]} as polynomial {plain.ToString()}");
                evaluator.AddInplace(encryptedTotal, encrypted);
            }
            Console.WriteLine("Done");

            Console.WriteLine("-----------------------------------");
            Plaintext plainResult = new Plaintext();
            decryptor.Decrypt(encryptedTotal, plainResult);
            Console.Write($"Decrypting the result polynomial {plainResult.ToString()} ... ");
            Console.WriteLine("Done");

            Console.WriteLine("-----------------------------------");
            Console.WriteLine($"Decoded result: {encoder.DecodeInt32(plainResult)}");
            Console.ReadLine();
        }

        static SEALContext createContext()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 2048;
            parms.CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 2048);
            parms.PlainModulus = new SmallModulus(1 << 8);
            return SEALContext.Create(parms);
        }

        static int[] createSampleVotes(int size)
        {
            Random random = new Random();
            int[] votes = new int[size];
            for (int i = 0; i < size; i++)
            {
                votes[i] = (int) random.Next(1, 100);
            }
            return votes;
        }

    }
}


