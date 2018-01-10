import org.shredzone.acme4j.*
import org.shredzone.acme4j.challenge.Dns01Challenge
import org.shredzone.acme4j.toolbox.AcmeUtils
import org.shredzone.acme4j.util.CSRBuilder
import org.shredzone.acme4j.util.KeyPairUtils
import java.io.File
import java.io.FileInputStream
import java.io.FileReader
import java.io.FileWriter
import java.net.URL
import java.nio.file.Files
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.Period
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import java.time.temporal.TemporalUnit

fun main(args: Array<String>) {

    val domainList = args

    val keyPairFile = File("file/keypair.pem")
    val keypair =
            if (keyPairFile.exists()) {
                KeyPairUtils.readKeyPair(FileReader(keyPairFile))
            } else {
                KeyPairUtils.createKeyPair(2048).apply {
                    FileWriter(keyPairFile).use {
                        KeyPairUtils.writeKeyPair(this, it)
                    }
                }
            }

    val session = Session("https://acme-staging-v02.api.letsencrypt.org/directory", keypair)

    val locationFile = File("file/accountLocation.txt")
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

    val certPath = Paths.get("file/wc-example-chain.crt")
    if(Files.exists(certPath)){
        val oldCert = FileInputStream(certPath.toFile()).use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }
        val expiryDate = LocalDateTime.ofInstant(oldCert.notAfter.toInstant(), ZoneId.systemDefault()).toLocalDate()
        val today = LocalDate.now()
        val period = ChronoUnit.DAYS.between(today, expiryDate)
        if(period > 30) return
    }

    val order = account.newOrder()
            .domains(*domainList)
            .create()
    for(auth in order.authorizations){
        auth.update()
        if(auth.status == Status.VALID){
            continue
        }
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
    }

    val domainKeyPairFile = File("file/domainKeypair.pem")
    val domainKeypair =
            if (domainKeyPairFile.exists()) {
                KeyPairUtils.readKeyPair(FileReader(domainKeyPairFile))
            } else {
                KeyPairUtils.createKeyPair(2048).apply {
                    FileWriter(domainKeyPairFile).use {
                        KeyPairUtils.writeKeyPair(this, it)
                    }
                }
            }

    val csrb = CSRBuilder()
    csrb.addDomains(*domainList)
    csrb.sign(domainKeypair)
    FileWriter("file/wc-example.csr").use {
        csrb.write(it)
    }
    order.execute(csrb.encoded)

    val cert = order.certificate
    FileWriter("file/wc-example-chain.crt").use {
        cert.writeCertificate(it)
    }
}