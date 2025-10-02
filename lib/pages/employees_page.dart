import 'package:flutter/material.dart';
import '../models.dart';
import '../api_service.dart';

class EmployeesPage extends StatefulWidget {
  @override
  State createState() => _EmployeesPageState();
}

class _EmployeesPageState extends State<EmployeesPage> {
  List<Employee> employees = [];
  bool loading = true;
  final nameCtrl = TextEditingController();
  String type = 'monthly';

  @override
  void initState(){ super.initState(); load(); }

  Future<void> load() async {
    setState(() => loading = true);
    employees = await ApiService.fetchEmployees();
    setState(() => loading = false);
  }

  Future<void> addEmployee() async {
    final name = nameCtrl.text.trim();
    if (name.isEmpty) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('ادخل الاسم'))); return; }
    try {
      await ApiService.createEmployee(name, type);
      nameCtrl.clear();
      await load();
    } catch (e) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('خطأ: $e'))); }
  }

  @override
  Widget build(BuildContext context){
    return Scaffold(
      appBar: AppBar(title: Text('الموظفين')),
      body: loading ? Center(child: CircularProgressIndicator()) : Padding(
        padding: EdgeInsets.all(12),
        child: Column(children: [
          TextField(controller: nameCtrl, decoration: InputDecoration(labelText: 'اسم الموظف')),
          Row(children: [
            Expanded(child: RadioListTile<String>(title: Text('تناوب شهري'), value: 'monthly', groupValue: type, onChanged: (v){ setState(()=>type=v!); })),
            Expanded(child: RadioListTile<String>(title: Text('ثابت'), value: 'fixed', groupValue: type, onChanged: (v){ setState(()=>type=v!); })),
          ]),
          ElevatedButton(onPressed: addEmployee, child: Text('إضافة موظف')),
          SizedBox(height: 12),
          Expanded(
            child: ListView.builder(
              itemCount: employees.length,
              itemBuilder: (_,i){
                final e = employees[i];
                return Card(child: ListTile(title: Text(e.name), subtitle: Text(e.employeeType)));
              }
            ),
          )
        ]),
      ),
    );
  }
}
