#!/usr/bin/env swift

import Foundation

func main() {
    if CommandLine.argc != 5 {
        let help = "Invoke the script with `swift updateFiles <ref sub> <checksum sub> <input_file_path> <output_file_path>`"
        print("Wrong number of arguments.\n\(help)")
        exit(1)
    }

    let args = CommandLine.arguments
    let ref = args[1]
    let checksum = args[2]
    let inputPath = args[3]
    let outputPath = args[4]

    do {
        // Read the content of the file
        let fileContent = try String(contentsOfFile: inputPath, encoding: .utf8)
        
        // Replace <ref> and <checksum> with specified values
        let updatedContent = fileContent.replacingOccurrences(of: "<ref>", with: ref)
                                         .replacingOccurrences(of: "<checksum>", with: checksum)
        
        // Write the updated content to the output file
        try updatedContent.write(toFile: outputPath, atomically: true, encoding: .utf8)
        print("File updated successfully.")
    } catch {
        print("An error occurred: \(error.localizedDescription)")
    }
}

main()
