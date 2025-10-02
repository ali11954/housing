import 'package:flutter/material.dart';
import '../api_service.dart';
import '../models.dart';
import '../widgets/stat_card.dart';
import 'dormitories_page.dart';
import 'employees_page.dart';

class DashboardPage extends StatefulWidget {
  @override
  State createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  bool loading = true;
  List<Dormitory> dorms = [];
  int totalRooms = 0;
  int totalBeds = 0;
  int occupiedBeds = 0;

  @override
  void initState() {
    super.initState();
    loadAll();
  }

  Future<void> loadAll() async {
    setState(() => loading = true);
    dorms = await ApiService.fetchDormitories();
    // اجمع إحصائيات بسيطة عبر جلب الغرف لكل سكن
    totalRooms = 0;
    totalBeds = 0;
    occupiedBeds = 0;
    for (var d in dorms) {
      final rooms = await ApiService.fetchRooms(dormitoryId: d.id);
      totalRooms += rooms.length;
      // لكل غرفة نحسب السعة (capacity) كمؤشر للأسرة
      for (var r in rooms) {
        totalBeds += r.capacity;
        occupiedBeds += r.occupied;
      }
    }
    setState(() => loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('لوحة التحكم')),
      drawer: Drawer(
        child: ListView(
          children: [
            DrawerHeader(child: Text('إدارة السكن', style: TextStyle(fontSize: 20))),
            ListTile(title: Text('السكنات'), onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => DormitoriesPage()))),
            ListTile(title: Text('الموظفين'), onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => EmployeesPage()))),
          ],
        ),
      ),
      body: loading ? Center(child: CircularProgressIndicator()) : RefreshIndicator(
        onRefresh: loadAll,
        child: SingleChildScrollView(
          physics: AlwaysScrollableScrollPhysics(),
          padding: EdgeInsets.all(12),
          child: Column(
            children: [
              GridView.count(
                shrinkWrap: true,
                physics: NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                crossAxisSpacing: 8,
                mainAxisSpacing: 8,
                children: [
                  StatCard(title: 'عدد المساكن', value: '${dorms.length}', icon: Icons.home, color: Colors.blue),
                  StatCard(title: 'عدد الغرف', value: '$totalRooms', icon: Icons.meeting_room, color: Colors.orange),
                  StatCard(title: 'إجمالي الأسرة', value: '$totalBeds', icon: Icons.bed, color: Colors.teal),
                  StatCard(title: 'الأسرّة المحجوزة', value: '$occupiedBeds', icon: Icons.person, color: Colors.red),
                ],
              ),
              SizedBox(height: 20),
              Text('قائمة السكنات', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              ...dorms.map((d) => ListTile(
                title: Text(d.name),
                subtitle: Text('سعة: ${d.capacity}  | محجوزة: ${d.occupied}'),
                trailing: Icon(Icons.chevron_right),
                onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => DormitoriesPage(initialDormId: d.id))),
              )).toList(),
            ],
          ),
        ),
      ),
    );
  }
}
