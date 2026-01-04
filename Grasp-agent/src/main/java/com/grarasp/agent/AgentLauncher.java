package com.grarasp.agent;

import com.grarasp.core.GraspCore;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.util.jar.JarFile;

/**
 * Agent 入口类 - 修复版
 * 关键修复：主动重转换 ClassLoader，确保 defineClass Hook 生效
 */
public class AgentLauncher {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("    _______  ___________  __________  ___   _____ ____ ");
        System.out.println("   / ____/ |/ / ____/   |/  _/  _/  |/  / | / / // / / ");
        System.out.println("  / / __/    / __/ / /| |  / / / / / /|_/ /  |/ / // /_");
        System.out.println(" / /_/ /   |/ /___/ ___ |_/ /_/ / / /  / / /|  /__  __/");
        System.out.println(" \\____/_/|_/_____/_/  |_/___/___/_/  /_/_/ |_/   /_/   ");
        System.out.println("                                                       ");
        System.out.println("                 GraRasp Agent V1.0.3                  ");

        try {
            File agentJarFile = getAgentJarFile();
            if (agentJarFile != null) {
                // System.out.println("[GraRasp] Append to bootstrap: " + agentJarFile.getAbsolutePath());
                inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJarFile));
            } else {
                System.err.println("[GraRasp] Error: Can not find agent jar file!");
            }

            // 1. 初始化核心模块
            GraspCore.init();

            // 2. 注册字节码转换器 (注意：第二个参数 true 表示支持重转换)
            inst.addTransformer(new GraspTransformer(), true);

            // 3. [核心修复] 强制重转换核心类
            // 因为 ClassLoader 在 Agent 启动前已加载，必须显式触发 retransform 才能 Hook 到 defineClass
            System.out.println("[GraRasp] Retransforming java.lang.ClassLoader...");
            inst.retransformClasses(java.lang.ClassLoader.class);

            // 如果需要防御 ProcessBuilder RCE，最好也重转换一下 (防止它也被提前加载)
            inst.retransformClasses(java.lang.ProcessBuilder.class);

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
}