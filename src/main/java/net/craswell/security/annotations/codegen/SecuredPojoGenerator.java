package net.craswell.security.annotations.codegen;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;

import javax.persistence.Transient;

import com.squareup.javapoet.AnnotationSpec;
import com.squareup.javapoet.CodeBlock;
import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterSpec;
import com.squareup.javapoet.TypeName;
import com.squareup.javapoet.TypeSpec;

import net.craswell.common.BinarySerializer;
import net.craswell.common.BinarySerializerException;
import net.craswell.common.codegen.BasicPojoGenerator;
import net.craswell.common.encryption.AesTool;
import net.craswell.common.encryption.AesToolException;
import net.craswell.common.encryption.AesToolImpl;
import net.craswell.common.encryption.PassphraseProvider;

import net.craswell.security.annotations.Confidential;
import net.craswell.security.annotations.RequiresConfidentiality;

/**
 * Creates secured POJO classes by looking for the presence of annotations on template classes.
 * 
 * Specifically, this generator looks for the following annotations: &amp;Confidential
 * 
 * @author scraswell@gmail.com
 *
 */
public class SecuredPojoGenerator
    extends BasicPojoGenerator {
  /**
   * The suffix to be appended to the template class.
   */
  private static final String SUFFIX = "Secured";

  /**
   * The passphrase provider field name.
   */
  private static final String PASSPHRASE_PROVIDER_FIELD_NAME = "passphraseProvider";

  /**
   * @return The predicate for filtering annotations when copying.
   */
  @Override
  protected Predicate<AnnotationMirror> getAnnotationFilter() {
    return annotationMirror -> {
      TypeName requiresConfidentiality = TypeName.get(RequiresConfidentiality.class);
      TypeName confidential = TypeName.get(Confidential.class);
      TypeName annotationTypeName =
          TypeName.get(annotationMirror.getAnnotationType().asElement().asType());

      boolean isFilteredAnnotation =
          requiresConfidentiality.toString().equals(annotationTypeName.toString())
              || confidential.toString().equals(annotationTypeName.toString());

      // System.out.println(requiresConfidentiality.toString());
      // System.out.println(confidential.toString());
      // System.out.println(annotationTypeName.toString());
      // System.out.println(isFilteredAnnotation);

      return !isFilteredAnnotation;
    };
  };

  /**
   * The Encryption tool interface.
   */
  private static final Class<?> EncryptionToolInterface = AesTool.class;

  /**
   * The Encryption tool class.
   */
  private static final Class<?> EncryptionToolImplementation = AesToolImpl.class;

  /**
   * The type of exception thrown by the encryption tool.
   */
  private static final Class<? extends Exception> EncryptionToolException = AesToolException.class;

  /**
   * The type of exception thrown by the encryption tool.
   */
  private static final Class<? extends Exception> SerializerException =
      BinarySerializerException.class;

  /**
   * Gets the suffix to append to specific generated members.
   * 
   * @return The suffix to be appended to specific generated members.
   */
  @Override
  protected String getSuffix() {
    return SUFFIX;
  }

  /**
   * Processes all fields from the template class.
   * 
   * @param templateClass The template class.
   * @param typeSpecBuilder The type spec builder.
   */
  @Override
  protected void processTemplateClassFields(
      TypeElement typeElement,
      TypeSpec.Builder typeSpecBuilder) {

    this.constructEncryptionSupportMembers(typeSpecBuilder);

    super.processTemplateClassFields(typeElement, typeSpecBuilder);
  }

  /**
   * Constructs the members required to support data confidentiality.
   * 
   * @param typeSpecBuilder The type spec builder.
   */
  protected void constructEncryptionSupportMembers(
      TypeSpec.Builder typeSpecBuilder) {
    typeSpecBuilder.addField(this.constructPassphraseProviderFieldSpec());
    typeSpecBuilder.addField(this.constructEncryptionToolFieldSpec());
    typeSpecBuilder.addMethod(this.constructBasicSetterSpecForFieldName(
        PASSPHRASE_PROVIDER_FIELD_NAME,
        TypeName.get(PassphraseProvider.class)));
    typeSpecBuilder.addMethod(this.constructSetterSpecForEncryptionTool());
  }

  /**
   * Constructs the setter specification for the encryption tool.
   * 
   * @return The setter method specification for the encryption tool.
   */
  protected MethodSpec constructSetterSpecForEncryptionTool() {
    MethodSpec.Builder methodSpecBuilder = this.constructBasicSetterSpecBuilderForFieldName(
        this.constructEncryptionToolFieldName(),
        TypeName.get(EncryptionToolInterface));

    methodSpecBuilder.addException(EncryptionToolException);

    return methodSpecBuilder
        .build();
  }

  /**
   * Creates a copy of the field and generates associated getters and setters.
   * 
   * @param typeSpecBuilder The type spec builder.
   * @param field The field.
   */
  @Override
  protected void processField(
      TypeSpec.Builder typeSpecBuilder,
      VariableElement field) {

    if (field.getAnnotation(Confidential.class) != null) {
      this.constructConfidentialitySupportMembers(
          typeSpecBuilder,
          field);
    } else {
      super.processField(typeSpecBuilder, field);
    }
  }

  /**
   * Constructs members required to support an instance of the Confidential annotation.
   * 
   * @param typeSpecBuilder The type spec builder.
   * @param field The confidential field.
   */
  protected void constructConfidentialitySupportMembers(
      TypeSpec.Builder typeSpecBuilder,
      VariableElement field) {

    String fieldName = field.getSimpleName()
        .toString();

    String securedFieldName = this.constructSecuredFieldName(fieldName);

    typeSpecBuilder
        // .addField(this.constructConfidentialFieldSpec(field))
        .addField(this.constructSecuredFieldSpec(field, securedFieldName))
        .addMethod(this.constructGetterMethodCapableOfDecryption(field))
        .addMethod(this.constructBasicSetterSpecForFieldName(
            securedFieldName,
            TypeName.get(String.class)))
        .addMethod(this.constructGetterForSecuredField(field))
        .addMethod(this.constructSetterForSecuredField(field));
  }

  protected MethodSpec constructGetterMethodCapableOfDecryption(VariableElement field) {
    String fieldName = field.getSimpleName().toString();

    Iterable<Modifier> modifiers = Arrays.asList(new Modifier[] {
        Modifier.PUBLIC,
    });

    Iterable<? extends TypeName> exceptionsThrown = Arrays.asList(
        TypeName.get(EncryptionToolException),
        TypeName.get(SerializerException));

    return this.constructMethodSpec(
        this.constructBasicGetterJavadoc(fieldName),
        this.determineGetterNameForFieldName(fieldName),
        modifiers,
        TypeName.get(field.asType()),
        (Iterable<AnnotationSpec>) null,
        exceptionsThrown,
        (Iterable<ParameterSpec>) null,
        this.constructGetterMethodCapableOfDecryptionBody(
            fieldName,
            TypeName.get(field.asType())));
  }
  
  protected CodeBlock constructGetterMethodCapableOfDecryptionBody(
      String fieldName,
      TypeName fieldTypeName) {
    String encryptionToolFieldName = this.constructEncryptionToolFieldName();
    String encryptionToolSetterName = this.determineSetterNameForFieldName(encryptionToolFieldName);

    String securedFieldName = this.constructSecuredFieldName(fieldName);

    String illegalStateExceptionMessage = "The passphrase provider has not been set.";
    String binaryObjectName = "binaryObject";
    String passphraseName = "passphrase";

    return CodeBlock.builder()
        .add(
            "if (this.$L == null) {\n  throw new IllegalStateException(\"$L\");\n}\n\n",
            PASSPHRASE_PROVIDER_FIELD_NAME,
            illegalStateExceptionMessage)
        .add(
            "if (this.$L == null) {\n  this.$L(new $T());\n}\n\n",
            encryptionToolFieldName,
            encryptionToolSetterName,
            EncryptionToolImplementation)
        .addStatement(
            "String $L = this.$L.getPassphrase()",
            passphraseName,
            PASSPHRASE_PROVIDER_FIELD_NAME)
        .addStatement(
            "byte[] $L = this.$L.decrypt(\nthis.$L.decodeObject(this.$L),\n$L)",
            binaryObjectName,
            encryptionToolFieldName,
            encryptionToolFieldName,
            securedFieldName,
            passphraseName)
        .addStatement(
            "$L = null",
            passphraseName)
        .addStatement(
            "return ($T) $T.deserializeObject($L)",
            fieldTypeName,
            BinarySerializer.class,
            binaryObjectName)
        .build();
  }

  /**
   * Constructs the setter specification for a secured field.
   * 
   * @param field The field to be secured.
   * 
   * @return The setter specification for a secured field.
   */
  protected MethodSpec constructSetterForSecuredField(VariableElement field) {
    String fieldName = field.getSimpleName().toString();

    Iterable<Modifier> modifiers = Arrays.asList(new Modifier[] {
        Modifier.PUBLIC,
    });

    Iterable<? extends TypeName> exceptionsThrown = Arrays.asList(
        TypeName.get(EncryptionToolException),
        TypeName.get(SerializerException));

    return this.constructMethodSpec(
        this.constructBasicSetterJavadoc(fieldName),
        this.determineSetterNameForFieldName(fieldName),
        modifiers,
        (TypeName) null,
        (Iterable<AnnotationSpec>) null,
        exceptionsThrown,
        this.constructBasicSetterParameters(fieldName, TypeName.get(field.asType())),
        this.constructConfidentialSetterMethodBody(fieldName));
  }

  /**
   * Constructs the confidential setter method body.
   * 
   * @param fieldName The confidential field name.
   * 
   * @return The confidential setter method body.
   */
  protected CodeBlock constructConfidentialSetterMethodBody(String fieldName) {
    String encryptionToolFieldName = this.constructEncryptionToolFieldName();
    String encryptionToolSetterName = this.determineSetterNameForFieldName(encryptionToolFieldName);

    String illegalStateExceptionMessage = "The passphrase provider has not been set.";
    String binaryObjectName = "binaryObject";
    String passphraseName = "passphrase";

    return CodeBlock.builder()
        .add(
            "if (this.$L == null) {\n  throw new IllegalStateException(\"$L\");\n}\n\n",
            PASSPHRASE_PROVIDER_FIELD_NAME,
            illegalStateExceptionMessage)
        .add(
            "if (this.$L == null) {\n  this.$L(new $T());\n}\n\n",
            encryptionToolFieldName,
            encryptionToolSetterName,
            EncryptionToolImplementation)
        .addStatement(
            "byte[] $L = $T.serializeObject($L)",
            binaryObjectName,
            BinarySerializer.class,
            fieldName)
        .addStatement(
            "String $L = this.$L.getPassphrase()",
            passphraseName,
            PASSPHRASE_PROVIDER_FIELD_NAME)
        .addStatement(
            "this.$L = this.$L.encodeObject(\nthis.$L.encrypt($L, $L))",
            this.constructSecuredFieldName(fieldName),
            encryptionToolFieldName,
            encryptionToolFieldName,
            binaryObjectName,
            passphraseName)
        .addStatement(
            "$L = null",
            passphraseName)
        .build();
  }

  /**
   * Constructs the getter specification for a secured field.
   * 
   * @param field The field to be secured.
   * 
   * @return The setter specification for a secured field.
   */
  protected MethodSpec constructGetterForSecuredField(VariableElement field) {
    String fieldName = field.getSimpleName().toString();

    String securedFieldName = this.constructSecuredFieldName(fieldName);

    Iterable<Modifier> modifiers = Arrays.asList(new Modifier[] {
        Modifier.PUBLIC,
    });

    return this.constructMethodSpec(
        this.constructBasicGetterJavadoc(securedFieldName),
        this.determineGetterNameForFieldName(securedFieldName),
        modifiers,
        TypeName.get(String.class),
        (Iterable<AnnotationSpec>) null,
        (Iterable<? extends TypeName>) null,
        (Iterable<ParameterSpec>) null,
        this.constructBasicGetterMethodBody(securedFieldName));
  }

  /**
   * Creates the secured field specification for a given field.
   * 
   * @param field The field.
   * @param securedFieldName The secured field name.
   * 
   * @return The secured field specification.
   */
  protected FieldSpec constructSecuredFieldSpec(
      VariableElement field,
      String securedFieldName) {

    List<Modifier> fieldModifiers = new ArrayList<Modifier>(field.getModifiers());

    return FieldSpec.builder(
        String.class,
        securedFieldName,
        fieldModifiers.toArray(new Modifier[fieldModifiers.size()]))
        .addAnnotations(this.copyAnnotations(field))
        .build();
  }

  /**
   * Creates the secured field specification for a given field.
   * 
   * @param field The field.
   * @param securedFieldName The secured field name.
   * 
   * @return The secured field specification.
   */
  protected FieldSpec constructConfidentialFieldSpec(VariableElement field) {
    field.getModifiers();

    List<Modifier> fieldModifiers = new ArrayList<Modifier>(field.getModifiers());

    fieldModifiers.add(Modifier.TRANSIENT);

    return FieldSpec.builder(
        TypeName.get(field.asType()),
        field.getSimpleName().toString(),
        fieldModifiers.toArray(new Modifier[fieldModifiers.size()]))
        .addAnnotations(Arrays.asList(AnnotationSpec.builder(Transient.class).build()))
        .build();
  }

  /**
   * Creates the passphrase provider field specification.
   * 
   * @return The passphrase provider field specification.
   */
  private FieldSpec constructPassphraseProviderFieldSpec() {
    return this.constructTransientFieldSpec(
        PASSPHRASE_PROVIDER_FIELD_NAME,
        TypeName.get(PassphraseProvider.class));
  }

  /**
   * Creates the encryption tool field.
   * 
   * @return The encryption tool field.
   */
  private FieldSpec constructEncryptionToolFieldSpec() {
    return this.constructTransientFieldSpec(
        this.constructEncryptionToolFieldName(),
        TypeName.get(EncryptionToolInterface));
  }

  /**
   * Creates a transient field given a name and type.
   * 
   * @param fieldName The name of the transient field.
   * @param fieldType The type of the transient field.
   * 
   * @return The transient field specification.
   */
  private FieldSpec constructTransientFieldSpec(
      String fieldName,
      TypeName fieldType) {

    return this.constructField(
        fieldName,
        fieldType,
        new Modifier[] {Modifier.PRIVATE, Modifier.TRANSIENT},
        Arrays.asList(AnnotationSpec.builder(Transient.class).build()));
  }

  /**
   * Builds the secured field name from the template field name.
   * 
   * @param fieldName The template field name.
   * 
   * @return The secured field name.
   */
  private String constructSecuredFieldName(String fieldName) {
    return String.format(
        "%1$s%2$s",
        fieldName,
        SUFFIX);
  }

  /**
   * Builds the encryption tool field name.
   * 
   * @return
   */
  private String constructEncryptionToolFieldName() {
    return this.firstLetterToLowerCase(
        EncryptionToolInterface.getSimpleName());
  }
}
