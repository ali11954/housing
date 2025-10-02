import 'package:flutter/material.dart';
import 'pages/dashboard_page.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Dorm Manager',
      theme: ThemeData(useMaterial3: true),
      home: DashboardPage(),
    );
  }
}
