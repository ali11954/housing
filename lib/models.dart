class Dormitory {
  final int id;
  final String name;
  final int capacity;
  final int occupied;
  Dormitory({required this.id, required this.name, required this.capacity, required this.occupied});

  factory Dormitory.fromJson(Map<String, dynamic> j) {
    return Dormitory(
      id: j['id'],
      name: j['name'],
      capacity: j['capacity'],
      occupied: j['occupied'] ?? 0,
    );
  }
}

class Room {
  final int id;
  final String name;
  final int dormitoryId;
  final int capacity;
  final int occupied;
  Room({required this.id, required this.name, required this.dormitoryId, required this.capacity, required this.occupied});
  factory Room.fromJson(Map<String, dynamic> j){
    return Room(
      id: j['id'],
      name: j['name'],
      dormitoryId: j['dormitory_id'],
      capacity: j['capacity'],
      occupied: j['occupied'] ?? 0,
    );
  }
}

class Bed {
  final int id;
  final String bedNumber;
  final int roomId;
  Bed({required this.id, required this.bedNumber, required this.roomId});
  factory Bed.fromJson(Map<String, dynamic> j){
    return Bed(id: j['id'], bedNumber: j['bed_number'], roomId: j['room_id']);
  }
}

class Employee {
  final int id;
  final String name;
  final String employeeType;
  Employee({required this.id, required this.name, required this.employeeType});
  factory Employee.fromJson(Map<String, dynamic> j){
    return Employee(id: j['id'], name: j['name'], employeeType: j['employee_type']);
  }
}

class Assignment {
  final int id;
  final int bedId;
  final int employeeId;
  final String startDate;
  final String? endDate;
  final bool isActive;
  Assignment({required this.id, required this.bedId, required this.employeeId, required this.startDate, this.endDate, required this.isActive});
  factory Assignment.fromJson(Map<String,dynamic> j){
    return Assignment(
      id: j['id'],
      bedId: j['bed_id'],
      employeeId: j['employee_id'],
      startDate: j['start_date'].toString(),
      endDate: j['end_date']?.toString(),
      isActive: j['is_active'] ?? true
    );
  }
}
