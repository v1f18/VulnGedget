package org.vulngedget.util;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.apache.commons.io.IOUtils;
import org.vulngedget.reference.MethodReference;
import org.vulngedget.reference.PathReference;

import java.io.*;
import java.util.List;

import static org.vulngedget.cache.DataCache.*;

public class TemplateUtil {
    public static void getHtml() throws IOException, TemplateException {
        Configuration configuration = new Configuration(Configuration.VERSION_2_3_28);
        configuration.setClassForTemplateLoading(TemplateUtil.class,"/templates");
        Template template = configuration.getTemplate("test.ftl");
        StringWriter stringWriter = new StringWriter();
        template.process(maybeVulnMapFlows,stringWriter);
        FileOutputStream fileOutputStream = new FileOutputStream(new File("out2.html"));
        IOUtils.write(stringWriter.toString(),fileOutputStream);
    }

    public static void getJsonResult() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("result.txt");
        for (String v : maybeVulnMapFlows.keySet()) {
            IOUtils.write(v+"\n",fileOutputStream);
            for (List<MethodReference> methodReferences : maybeVulnMapFlows.get(v)) {
                for (MethodReference methodReference : methodReferences) {
                    IOUtils.write(methodReference.className+"#"+methodReference.methodName+"\n",fileOutputStream);
                }
                IOUtils.write("---------------------------\n",fileOutputStream);
            }
        }
    }

    public static void getWebPath() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("webpath.txt");
        for (PathReference pathReference : methodPath) {
            List list = classPath.get(pathReference.className);
            if (list.size()!=0){
                String p1 = (String) list.get(0);
                p1 = p1.replace("**", "");
                if (pathReference.paths.size()!=0){
                for (Object path : pathReference.paths) {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+p1+path+"\n",fileOutputStream);
                }
                }else {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+p1+"\n",fileOutputStream);

                }
            }else {
                for (Object path : pathReference.paths) {
                    IOUtils.write(pathReference.className+"#"+ pathReference.methodName+"--->"+path+"\n",fileOutputStream);

                }
            }
        }
    }
    public static void getAllFlow() throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream("allFlow.txt");

        for (List<MethodReference> sortMethod : sortMethods) {
            for (MethodReference methodReference : sortMethod) {
                IOUtils.write(methodReference.className+"#"+methodReference.methodName+"\n",fileOutputStream);
            }
            IOUtils.write("---------------------------"+'\n',fileOutputStream);
        }
    }
}
