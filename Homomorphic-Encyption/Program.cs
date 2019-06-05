using System;

namespace Homomorphic_Encyption
{
    class Program
    {
        static void Main(string[] args)
        {

            int size = 512;
            UInt64 p = getP(size);
            UInt64 g = getG(size);

            int votersCount = 5;
            ulong[] v = createSampleVotes(votersCount);
            ulong[] x = createSamplePrivateValues(votersCount);
            // Voting keys (broadcast by each voter)
            ulong[] y = createVotingKeys(g, p, x);
            // Voter values
            ulong[] V = createVotingKeys(g, p, v);
            // Each voter calculates Y[i]
            ulong[] Y = calculateY(g, p, y);
            ulong[] registeredVotes = calculateVotes(Y, x, V, p);
            ulong result = calculateResult(registeredVotes, p);
            bruteforce(result, g, p);

            double ss = Math.Pow(g, x[0]);
            ulong sss = (ulong) ss;
            ulong xxx = sss % p;


            Console.WriteLine("p={0}, g={1}", p, g);
            Console.WriteLine("v=[{0}]", string.Join(", ", v));
            Console.WriteLine("x=[{0}]", string.Join(", ", x));
            Console.WriteLine("y=[{0}]", string.Join(", ", y));
            Console.WriteLine("V=[{0}]", string.Join(", ", V));
            Console.WriteLine("Y=[{0}]", string.Join(", ", Y));
            Console.WriteLine("registeredVotes=[{0}]", string.Join(", ", registeredVotes));
            Console.WriteLine("result=[{0}]", result);
            Console.ReadLine();
        }

        static void bruteforce(ulong result, ulong g, ulong p)
        {
            for (int i = 0; i < 10000; i++)
            {
                ulong gm = ((ulong) Math.Pow(g, i)) % p;

                if (result.Equals(gm))
                {
                    Console.WriteLine("Total votes: {0}", result);
                }
            }
        }

        static ulong calculateResult(ulong[] registeredVotes, ulong p)
        {
            ulong result = 1;

            for (int i = 0; i < registeredVotes.Length; i++)
            {
                result *= registeredVotes[i];
            }
            return result % p;
        }

        static ulong[] calculateVotes(ulong[] Y, ulong[] x, ulong[] V, ulong p)
        {
            ulong[] registeredVotes = new ulong[Y.Length];
            for (int i = 0; i < Y.Length; i++)
            {
                registeredVotes[i] = ((ulong)Math.Pow(Y[i], x[i])) % p * V[i];
            }
            return registeredVotes;
        }

        static ulong[] calculateY(ulong g, ulong p, ulong[] y)
        {
            ulong[] Y = new ulong[y.Length];

            for (int i = 0; i < y.Length; i++)
            {
                ulong res = 1;

                for (int j = 0; j <= i-1; j++)
                {
                    res *= y[j];
                    //res = res % p;
                }

                for (int j = i+1; j < y.Length; j++)
                {
                    res *= 1/y[j];
                    //res = res % p;
                }

                Y[i] = res % p;
            }

            return Y;
        }

        static ulong[] createVotingKeys(ulong g, ulong p, ulong[] x)
        {
            ulong[] y = new ulong[x.Length];
            for (int i = 0; i < x.Length; i++)
            {
                y[i] = makeG(g, x[i], p);
            }
            return y;
        }

        static ulong[] createSampleVotes(int size)
        {
            Random random = new Random();
            ulong[] votes = new ulong[size];
            for (int i = 0; i < size; i++) {
                votes[i] = (ulong) random.Next(1, 3);
            }
            return votes;
        }

        static ulong[] createSamplePrivateValues(int size)
        {
            Random random = new Random();
            ulong[] votes = new ulong[size];
            for (int i = 0; i < size; i++)
            {
                votes[i] = (ulong) random.Next(1, 10);
            }
            return votes;
        }

        static ulong makeG(ulong g, ulong v, ulong p)
        {
            return ((ulong) Math.Pow(g, v)) % p;
        }

        static UInt64 hexToInt(string hexValue)
        {
            return Convert.ToUInt64(hexValue, 16);
        }

        // TODO
        static UInt64 getG(int size)
        {
            if (size.Equals(512))
            {
                return hexToInt("67");
            }
            else if (size.Equals(768)) {
                return hexToInt("30");
            }
            else if (size.Equals(1024)) {
                return hexToInt("F7");
            }
            return 0;
        }

        static UInt64 getP(int size)
        {
            if (size.Equals(512)) {
                return hexToInt("FC");
            } else if (size.Equals(768)) {
                return hexToInt("E9");
            } else if (size.Equals(1024)) {
                return hexToInt("FD");
            }
            return 0;
        }
    }
}
