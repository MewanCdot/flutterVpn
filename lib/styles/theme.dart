// lib/styles/theme.dart

import 'package:flutter/material.dart';

class AppColors {
  static const Color primaryColor = Color(0xFF0078a1); // Primary color
  static const Color secondaryColor = Color.fromARGB(214, 235, 144, 144);
  static const Color accentColor = Color(0xFF96BDC2); // Example accent color
  static const Color backgroundColor = Color(0xFFFFFFFF);
  static const Color textColor = Color(0xFF000000);
}

ThemeData lightTheme = ThemeData(
  primaryColor: AppColors.primaryColor,
  scaffoldBackgroundColor: AppColors.backgroundColor,
  colorScheme: ColorScheme.light(
    primary: AppColors.primaryColor,
    secondary: AppColors.secondaryColor, // Set secondary color
  ),
  textTheme: TextTheme(
    bodyLarge: TextStyle(color: AppColors.textColor), // Use bodyLarge for body text
  ),
  appBarTheme: AppBarTheme(
    color: AppColors.primaryColor, // Set the app bar color
  ),
);

ThemeData darkTheme = ThemeData(
  brightness: Brightness.dark,
  primaryColor: AppColors.primaryColor,
  scaffoldBackgroundColor: Colors.black,
  colorScheme: ColorScheme.dark(
    primary: AppColors.primaryColor,
    secondary: AppColors.secondaryColor,
  ),
  textTheme: TextTheme(
    bodyLarge: TextStyle(color: Colors.white),
  ),
);
