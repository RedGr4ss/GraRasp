package com.grarasp.agent;

import com.grarasp.core.GraspCore;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;

/**
 * Agent entry point.
 */
public class AgentLauncher {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("    _______  ___________  __________  ___   _____ ____ ");
        System.out.println("   / ____/ |/ / ____/   |/  _/  _/  |/  / | / / // / / ");
        System.out.println("  / / __/    / __/ / /| |  / / / / / /|_/ /  |/ / // /_");
        System.out.println(" / /_/ /   |/ /___/ ___ |_/ /_/ / / /  / / /|  /__  __/");
        System.out.println(" \\____/_/|_/_____/_/  |_/___/___/_/  /_/_/ |_/   /_/   ");
        System.out.println("                                                       ");
        System.out.println("                 GraRasp Agent V1.5.0                  ");

        try {
            File agentJarFile = getAgentJarFile();
            if (agentJarFile != null) {
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarFile));
            } else {
                System.err.println("[GraRasp] Error: Can not find agent jar file!");
            }

            GraspCore.init();
            inst.addTransformer(new GraspTransformer(), true);

            // Retransform already loaded core classes to reduce startup blind spots.
            retransformLoadedClasses(inst,
                "java.lang.ClassLoader",
                "java.lang.ProcessBuilder",
                "java.lang.Runtime",
                "javax.naming.InitialContext",
                "javax.script.AbstractScriptEngine");

            System.out.println("[GraRasp] Install Success! Core classes hooked.");
        } catch (Throwable e) {
            System.err.println("[GraRasp] Install Failed!");
            e.printStackTrace();
        }
    }

    private static File getAgentJarFile() {
        try {
            URL location = AgentLauncher.class.getProtectionDomain().getCodeSource().getLocation();
            if (location != null) {
                return new File(location.toURI());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void retransformLoadedClasses(Instrumentation inst, String... classNames) {
        List<Class<?>> loadedTargets = new ArrayList<>();

        for (String className : classNames) {
            boolean found = false;
            for (Class<?> loadedClass : inst.getAllLoadedClasses()) {
                if (className.equals(loadedClass.getName())) {
                    found = true;
                    if (inst.isModifiableClass(loadedClass)) {
                        loadedTargets.add(loadedClass);
                    } else {
                        System.err.println("[GraRasp] Skip non-modifiable class: " + className);
                    }
                    break;
                }
            }

            if (!found) {
                System.out.println("[GraRasp] Class not loaded yet, hook will apply on first load: " + className);
            }
        }

        if (loadedTargets.isEmpty()) {
            return;
        }

        System.out.println("[GraRasp] Retransforming loaded core classes: " + loadedTargets.size());
        try {
            inst.retransformClasses(loadedTargets.toArray(new Class<?>[0]));
        } catch (Exception e) {
            System.err.println("[GraRasp] Retransforming loaded core classes failed");
            e.printStackTrace();
        }
    }
}
