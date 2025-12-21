package com.grarasp.agent;

import com.grarasp.core.GraspCore;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.jar.JarFile;

/**
 * Agent 入口类
 */
public class AgentLauncher {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("    _______  ___________  __________  ___   _____ ____ ");
        System.out.println("   / ____/ |/ / ____/   |/  _/  _/  |/  / | / / // / / ");
        System.out.println("  / / __/    / __/ / /| |  / / / / / /|_/ /  |/ / // /_");
        System.out.println(" / /_/ /   |/ /___/ ___ |_/ /_/ / / /  / / /|  /__  __/");
        System.out.println(" \\____/_/|_/_____/_/  |_/___/___/_/  /_/_/ |_/   /_/   ");
        System.out.println("                                                       ");
        System.out.println("                 GraRasp Agent V1.0.0                  ");

        try {
            File agentJarFile = getAgentJarFile();
            if (agentJarFile != null) {
                System.out.println("[GraRasp] Append to bootstrap: " + agentJarFile.getAbsolutePath());
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarFile));
            } else {
                System.err.println("[GraRasp] Error: Can not find agent jar file!");
            }

            // 1. 初始化核心模块
            GraspCore.init();

            // 2. 注册字节码转换器
            inst.addTransformer(new GraspTransformer(), true);

            System.out.println("[GraRasp] Install Success! Transformer registered.");

        } catch (Throwable e) {
            System.err.println("[GraRasp] Install Failed!");
            e.printStackTrace();
        }
    }

    /**
     * 获取当前 Agent Jar 文件的路径
     */
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
}