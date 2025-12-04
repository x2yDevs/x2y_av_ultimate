import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class X2yColors {
  static const Color background = Color(0xFF0F172A); // Slate 900
  static const Color sidebar = Color(0xFF1E293B);    // Slate 800
  static const Color utilityPane = Color(0xFF020617); // Darker Slate
  
  static const Color secure = Color(0xFF10B981);     // Green
  static const Color warning = Color(0xFFF59E0B);    // Amber
  static const Color threat = Color(0xFFEF4444);     // Red
  static const Color primary = Color(0xFF3B82F6);    // Blue
  
  static const Color textMain = Color(0xFFF8FAFC);
  static const Color textDim = Color(0xFF94A3B8);
}

class X2yTheme {
  static ThemeData get dark {
    final baseTheme = ThemeData.dark();
    
    return baseTheme.copyWith(
      scaffoldBackgroundColor: X2yColors.background,
      cardColor: X2yColors.sidebar,
      // FIXED: 'jetBrainsMonoTextTheme' (Correct casing with capital B)
      textTheme: GoogleFonts.jetBrainsMonoTextTheme(baseTheme.textTheme).apply(
        bodyColor: X2yColors.textMain,
        displayColor: X2yColors.textMain,
      ),
      colorScheme: const ColorScheme.dark(
        primary: X2yColors.primary,
        surface: X2yColors.sidebar,
        error: X2yColors.threat,
      ),
    );
  }
}