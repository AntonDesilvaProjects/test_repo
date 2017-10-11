
public class Runner {
	public static void main(String[] args)
	{
		final String filePath = "C:\\Users\\Anton\\Desktop\\student.txt";
		Student anton = new Student( 1, "Peprika De Silva" );
		SerializerFactory<Student> factory = new SerializerFactory<Student>();
		factory.serialize(anton, filePath );
	
		Student newStudent = factory.deserializeStudent( filePath );
		System.out.print(newStudent.getId() + "\t" + newStudent.getName() );
	}
}
---------------------
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

public class StudentObjectInputStream extends ObjectInputStream {

	public StudentObjectInputStream(InputStream inputStream) throws IOException {
		super(inputStream);
	}
	
	/**
     * Only deserialize instances of our expected Bicycle class
     */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException,
            ClassNotFoundException {
//        if (!desc.getName().equals(Student.class.getName())) {
//            throw new InvalidClassException(
//                    "Unauthorized deserialization attempt",
//                    desc.getName());
//        }
        return Student.class;
    }
	

}
------------------------------
import java.io.Serializable;

public class Student implements Serializable {
	
	private static final long serialversionUID =
            129348938L;
	
	private int id;
	private String name;
	
	public Student(int id, String name)
	{
		this.id = id;
		this.name = name;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
---------------\import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class SerializerFactory<T> {
	
	public void serialize(T obj, String filePath)
	{
		try {
			FileOutputStream output = new FileOutputStream( filePath );
			ObjectOutputStream objOutput = new ObjectOutputStream( output );
			objOutput.writeObject( obj );
			objOutput.flush();
			objOutput.close();
			System.out.println("Object succesfully serialized!");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public T deserialize(String filePath)
	{
		try {
			ObjectInputStream objInput = new ObjectInputStream(new FileInputStream(filePath));
			T obj = (T) objInput.readObject();
			objInput.close();
			System.out.println("Object Successfuly deserialized!");
			return obj;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	public Student deserializeStudent(String filePath)
	{
		try {
			ObjectInputStream objInput = new StudentObjectInputStream(new FileInputStream(filePath));
			Student obj = (Student) objInput.readObject();
			objInput.close();
			System.out.println("Object Successfuly deserialized!");
			return obj;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
