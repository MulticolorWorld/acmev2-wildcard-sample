import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.challenge.Dns01Challenge
import org.shredzone.acme4j.util.CSRBuilder
import org.shredzone.acme4j.util.KeyPairUtils
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.net.URL
import java.nio.file.Files

fun main(args: Array<String>) {
    val keyPairFile = File("file/keypair.pem")
    val keypair =
            if (keyPairFile.exists()) {
                KeyPairUtils.readKeyPair(FileReader(keyPairFile))
            } else {
                KeyPairUtils.createKeyPair(2048).apply {
                    FileWriter("file/keypair.pem").use {
                        KeyPairUtils.writeKeyPair(this, it)
                    }
                }
            }

    val session = Session("https://acme-staging-v02.api.letsencrypt.org/directory", keypair)

    val locationFile = File("file/location.txt")
    val account =
            if (locationFile.exists()) {
                Files.readAllLines(locationFile.toPath())[0].let {
                    Account.bind(session, URL(it))
                }
            } else {
                AccountBuilder().agreeToTermsOfService().create(session).apply {
                    FileWriter(locationFile).use {
                        it.write(this.location.toString())
                    }
                }
            }

    val order = account.newOrder()
            .domains("*.toot-counter.net")
            .create()
    val auth = order.authorizations[0]
    val challenge = auth.findChallenge<Dns01Challenge>(Dns01Challenge.TYPE)
    println(challenge.digest)
    challenge.trigger()
    while (challenge.status != Status.VALID && challenge.status != Status.INVALID) {
        Thread.sleep(10 * 1000L)
        challenge.update()
    }
    if (challenge.status == Status.INVALID) {
        throw RuntimeException("authorization failed.")
    }

    val csrb = CSRBuilder()
    csrb.addDomains("*.toot-counter.net")
    csrb.sign(KeyPairUtils.createKeyPair(2048))
    csrb.write(FileWriter("file/wc.toot-counter.net.csr"))
    order.execute(csrb.encoded)
    order.update()

    val cert = order.certificate
    cert.writeCertificate(FileWriter("file/wctoot-counter.net.chain.crt"))
}