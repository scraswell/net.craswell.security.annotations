package net.craswell.security.annotationProcessors;

import java.io.IOException;
import java.util.Set;

import javax.annotation.Generated;
import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.Messager;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.lang.model.util.Elements;
import javax.tools.Diagnostic.Kind;

import com.squareup.javapoet.JavaFile;

import net.craswell.security.annotations.RequiresConfidentiality;
import net.craswell.security.annotations.codegen.SecuredPojoGenerator;

/**
 * Processes elements found with supported attributes.
 * 
 * @author scraswell@gmail.com
 *
 */
@SupportedSourceVersion(SourceVersion.RELEASE_8)
@SupportedAnnotationTypes(value = {
    "net.craswell.security.annotations.Confidential",
    "net.craswell.security.annotations.RequiresConfidentiality"})
public class ConfidentialityProcessor
    extends AbstractProcessor {
  /**
   * Generates secured versions of classes. Fields marked with @Confidential will be encrypted.
   */
  private SecuredPojoGenerator securedPojoGenerator = new SecuredPojoGenerator();

  /**
   * The filer.
   */
  private Filer filer;

  /**
   * The processor messager.
   */
  private Messager messager;
  
  /**
   * Element utilities.
   */
  private Elements elementUtils;

  /*
   * (non-Javadoc)
   * 
   * @see javax.annotation.processing.AbstractProcessor#init(javax.annotation.processing.
   * ProcessingEnvironment)
   */
  @Override
  public synchronized void init(ProcessingEnvironment processingEnv) {
    super.init(processingEnv);

    this.elementUtils = processingEnv.getElementUtils();
    this.filer = processingEnv.getFiler();
    this.messager = processingEnv.getMessager();
  }

  /*
   * (non-Javadoc)
   * 
   * @see javax.annotation.processing.AbstractProcessor#process(java.util.Set,
   * javax.annotation.processing.RoundEnvironment)
   */
  @Override
  public boolean process(
      Set<? extends TypeElement> annotations,
      RoundEnvironment roundEnv) {

    for (Element elem : roundEnv.getElementsAnnotatedWith(RequiresConfidentiality.class)) {
      if (elem.getAnnotation(Generated.class) != null) {
        continue;
      }

      if (elem.getKind() == ElementKind.CLASS) {

        TypeElement typeElement = (TypeElement) elem;

        String noteMessage = String.format(
            "Creating proxy class for %1$s => %1$sSecured.",
            typeElement.getQualifiedName().toString());

        this.messager.printMessage(
            Kind.NOTE,
            noteMessage);

        JavaFile jf = null;

        String destinationPackageName = String.format(
            "%1$s.generated",
            this.elementUtils.getPackageOf(typeElement)
                .getQualifiedName()
                  .toString());

        jf = this.securedPojoGenerator.constructPojoSourceFileFromTypeElement(
            destinationPackageName,
            typeElement);

        if (jf != null) {
          try {
            jf.writeTo(this.filer);
          } catch (IOException e) {
            this.messager.printMessage(Kind.ERROR, "Exception occurred.");
            this.messager.printMessage(Kind.ERROR, e.getMessage());
            e.printStackTrace();
          }
        }
      }
    }

    return true;
  }
}
