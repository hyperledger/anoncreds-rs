require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "anoncreds"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => "https://github.com/hyperledger/anoncreds-rs", :tag => "#{s.version}" }

  s.header_mappings_dir = "cpp"

  s.pod_target_xcconfig = {
    :USE_HEADERMAP => "No"
  }

  s.ios.vendored_frameworks = "native/mobile/ios/anoncreds.xcframework"

  s.source_files = "ios/**/*.{h,m,mm}", "cpp/**/*.{h,cpp}"
  
  s.dependency "React-Core"
  s.dependency "React-callinvoker"
  s.dependency "React"
end
