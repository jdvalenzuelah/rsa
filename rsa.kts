#!/usr/bin/env kscript

//DEPS com.xenomachina:kotlin-argparser:2.0.7

import java.math.BigInteger
import java.security.SecureRandom
import com.xenomachina.argparser.ArgParser
import com.xenomachina.argparser.default
import com.xenomachina.argparser.mainBody
import java.io.File

object RSA {

    data class PublicKey(val n: BigInteger, val e: BigInteger)

    data class PrivateKey(val d: BigInteger, val n: BigInteger)

    data class KeyPair(val public: PublicKey, val private: PrivateKey)

    private val random = SecureRandom()
    private const val keyLength = 400

    private fun getRandomPrime(): BigInteger {
        return BigInteger.probablePrime(keyLength/2, random)
    }

    private tailrec fun gcd(a: BigInteger, b: BigInteger): BigInteger {
        val (m, n) = if(b > a) b to a else a to b

        return if(m % n == BigInteger.ZERO)     n else gcd(n, m % n)
    }

    private fun lcm(a: BigInteger, b: BigInteger): BigInteger = a.times(b).abs().div(gcd(a, b))

    private fun getE(lambda: BigInteger): BigInteger {
        return "65537".toBigInteger() //2^16 - 1
    }

    private fun String.asBigInteger() = BigInteger(this.toByteArray())

    private fun BigInteger.asString() = String(this.toByteArray())

    fun genKeyPair(): KeyPair {
        val p = getRandomPrime()
        val q = getRandomPrime()
        val lambda = lcm(p - BigInteger.ONE, q - BigInteger.ONE )
        val e = getE(lambda)
        val d = e.modInverse(lambda)
        val n = p*q
        return KeyPair(
            PublicKey(n, e),
            PrivateKey(d, n)
        )
    }

    fun encrypt(message: String, key: PublicKey): BigInteger = encrypt(message.asBigInteger(), key)
    private fun encrypt(message: BigInteger, key: PublicKey): BigInteger = message.modPow(key.e, key.n)

    fun decrypt(message: BigInteger, key: PrivateKey): String = message.modPow(key.d, key.n).asString()

}

fun RSA.PrivateKey.toFile(path: String): File {
    val file = File(path)
    file.writeText("$d/$n")
    return file
}

fun RSA.PublicKey.toFile(path: String): File {
    val file = File(path)
    file.writeText("$e/$n")
    return file
}

fun RSA.KeyPair.toFiles(publicPath: String, privatePath: String): Pair<File, File> {
    return public.toFile(publicPath) to private.toFile(privatePath)
}

fun File.toPublicKey(): RSA.PublicKey {
    val values = readText().split("/").map { it.toBigInteger() }
    require(values.size == 2) { "Unrecognized key format" }
    return RSA.PublicKey(e = values[0]!!, n = values[1]!!)
}

fun File.toPrivateKey(): RSA.PrivateKey {
    val values = readText().split("/").map { it.toBigInteger() }
    require(values.size == 2) { "Unrecognized key format" }
    return RSA.PrivateKey(d = values[0]!!, n = values[1]!!)
}

enum class Mode {
    GEN, DEC, ENC
}

private class Args(parser: ArgParser) {

    val mode by parser.mapping(
        "--keygen" to Mode.GEN,
        "--decrypt" to Mode.DEC,
        "--encrypt" to Mode.ENC,
        help = "Mode in which program will be executed"
    ).default(Mode.GEN)

    val privKey by parser.storing(
        "--privatekey",
        help = "Path of private key"
    ).default("key")

    val pubKey by parser.storing(
        "--publickey",
        help = "Path of private key"
    ).default("key.pub")

    val fileToProcess by parser.positional("FROM", help = "File to encrypt or decrypt").default("")
}


fun main(args: Array<String>) = mainBody {
    val scriptArgs = Args(ArgParser(args))

    when(scriptArgs.mode) {
        Mode.GEN -> RSA.genKeyPair().toFiles(scriptArgs.pubKey, scriptArgs.privKey)
        Mode.DEC -> {
            val key = File(scriptArgs.privKey).toPrivateKey()
            val fileContent = File(scriptArgs.fileToProcess).readText().removeSuffix("\n").toBigInteger()
            println(RSA.decrypt(fileContent, key))
        }
        Mode.ENC -> {
            val key = File(scriptArgs.pubKey).toPublicKey()
            val fileContent = File(scriptArgs.fileToProcess).readText()
            println(RSA.encrypt(fileContent, key))
        }
    }

}

main(args)
