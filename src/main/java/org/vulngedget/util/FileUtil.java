package org.vulngedget.util;

import org.codehaus.plexus.util.IOUtil;

import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class FileUtil {


    public static String getPath(String path){
        String property = System.getProperty("user.dir");
        return property+"/"+path;
    }

    public static void writeBytes(String path,byte[] data) throws IOException {
        File file = new File(path);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(data);
    }
    public static byte[] readBytes(String path) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(path);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        IOUtil.copy(bufferedInputStream,byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }

    public static ClassLoader getJarClassLoader(String jarPath) throws IOException {
        final List<URL> classPathUrls = new ArrayList<>();
        Path path = Paths.get(jarPath);
        if (!Files.exists(path) || Files.isDirectory(path)) {
                throw new IllegalArgumentException("Path \"" + jarPath + "\" is not a path to a file.");
            }
            classPathUrls.add(path.toUri().toURL());

        URLClassLoader classLoader = new URLClassLoader(classPathUrls.toArray(new URL[classPathUrls.size()]));
        return classLoader;
    }




}
