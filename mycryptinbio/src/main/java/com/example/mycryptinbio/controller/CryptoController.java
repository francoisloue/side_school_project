package com.example.mycryptinbio.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.example.mycryptinbio.service.CryptoService;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

@Controller
@RequestMapping("/crypto")
public class CryptoController {

    @Autowired
    private CryptoService cryptoService;

    @GetMapping
    public String index(Model model) {
        return "index";
    }

    @PostMapping("/generate-keys")
    public String generateKeys(Model model) throws NoSuchAlgorithmException, NoSuchProviderException {
        cryptoService.generateKeyPair();
        model.addAttribute("message", "Keys generated successfully.");
        return "index";
    }

    @PostMapping("/encrypt")
    public String encryptFile(@RequestParam("file") MultipartFile file, Model model) throws Exception {
        byte[] encryptedBytes = cryptoService.encryptFile(file.getBytes());
        model.addAttribute("encryptedData", new String(encryptedBytes));
        model.addAttribute("message", "File encrypted successfully.");
        return "index";
    }

    @PostMapping("/decrypt")
    public String decryptFile(@RequestParam("file") MultipartFile file, Model model) throws Exception {
        byte[] decryptedBytes = cryptoService.decryptFile(file.getBytes());
        model.addAttribute("decryptedData", new String(decryptedBytes));
        model.addAttribute("message", "File decrypted successfully.");
        return "index";
    }
}
