import 'dart:convert';
import 'package:http/http.dart' as http;
import 'config.dart';
import 'models.dart';

class ApiService {
  static Future<List<Dormitory>> fetchDormitories() async {
    final res = await http.get(Uri.parse('$API_BASE/dormitories/'));
    if (res.statusCode == 200) {
      final List data = json.decode(res.body);
      return data.map((e) => Dormitory.fromJson(e)).toList();
    } else {
      throw Exception('Failed to load dormitories');
    }
  }

  static Future<Dormitory> createDormitory(String name, int capacity) async {
    final res = await http.post(Uri.parse('$API_BASE/dormitories/'),
      headers: {'Content-Type':'application/json'},
      body: json.encode({'name': name, 'capacity': capacity}));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return Dormitory.fromJson(json.decode(res.body));
    } else {
      throw Exception('Create dormitory failed: ${res.body}');
    }
  }

  static Future<List<Room>> fetchRooms({int? dormitoryId}) async {
    final uri = dormitoryId == null ? Uri.parse('$API_BASE/rooms/') : Uri.parse('$API_BASE/rooms/?dormitory_id=$dormitoryId');
    final res = await http.get(uri);
    if (res.statusCode == 200) {
      final List data = json.decode(res.body);
      return data.map((e) => Room.fromJson(e)).toList();
    } else {
      throw Exception('Failed to load rooms');
    }
  }

  static Future<Room> createRoom(String name, int dormitoryId, int capacity) async {
    final res = await http.post(Uri.parse('$API_BASE/rooms/'),
      headers: {'Content-Type':'application/json'},
      body: json.encode({'name': name, 'dormitory_id': dormitoryId, 'capacity': capacity}));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return Room.fromJson(json.decode(res.body));
    } else {
      throw Exception('Create room failed: ${res.body}');
    }
  }

  static Future<List<Bed>> fetchBeds({int? roomId}) async {
    final uri = roomId == null ? Uri.parse('$API_BASE/beds/') : Uri.parse('$API_BASE/beds/?room_id=$roomId');
    final res = await http.get(uri);
    if (res.statusCode == 200) {
      final List data = json.decode(res.body);
      return data.map((e) => Bed.fromJson(e)).toList();
    } else {
      throw Exception('Failed to load beds');
    }
  }

  static Future<Bed> createBed(String bedNumber, int roomId) async {
    final res = await http.post(Uri.parse('$API_BASE/beds/'),
      headers: {'Content-Type':'application/json'},
      body: json.encode({'bed_number': bedNumber, 'room_id': roomId}));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return Bed.fromJson(json.decode(res.body));
    } else {
      throw Exception('Create bed failed: ${res.body}');
    }
  }

  static Future<List<Employee>> fetchEmployees() async {
    final res = await http.get(Uri.parse('$API_BASE/employees/'));
    if (res.statusCode == 200) {
      final List data = json.decode(res.body);
      return data.map((e) => Employee.fromJson(e)).toList();
    } else {
      throw Exception('Failed to load employees');
    }
  }

  static Future<Employee> createEmployee(String name, String type) async {
    final res = await http.post(Uri.parse('$API_BASE/employees/'),
      headers: {'Content-Type':'application/json'},
      body: json.encode({'name': name, 'employee_type': type}));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return Employee.fromJson(json.decode(res.body));
    } else {
      throw Exception('Create employee failed: ${res.body}');
    }
  }

  static Future<dynamic> assignBed(int bedId, int empId, String startDate, String? endDate) async {
    final res = await http.post(Uri.parse('$API_BASE/assignments/'),
      headers: {'Content-Type':'application/json'},
      body: json.encode({'bed_id': bedId, 'employee_id': empId, 'start_date': startDate, 'end_date': endDate}));
    if (res.statusCode == 200 || res.statusCode == 201) {
      return json.decode(res.body);
    } else {
      throw Exception('Assign failed: ${res.body}');
    }
  }

  static Future<List<dynamic>> fetchAssignments({int? employeeId, int? bedId}) async {
    final params = <String>[];
    if (employeeId != null) params.add('employee_id=$employeeId');
    if (bedId != null) params.add('bed_id=$bedId');
    final uri = params.isEmpty ? Uri.parse('$API_BASE/assignments/') : Uri.parse('$API_BASE/assignments/?${params.join('&')}');
    final res = await http.get(uri);
    if (res.statusCode == 200) {
      final List data = json.decode(res.body);
      return data;
    } else {
      throw Exception('Failed to load assignments');
    }
  }
}
