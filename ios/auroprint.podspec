Pod::Spec.new do |s|
  s.name             = 'auroprint'
  s.version          = '0.1.0'
  s.summary          = 'Spoof-proof device fingerprint generation'
  s.description      = <<-DESC
Spoof-proof device fingerprint generation with hardware-backed signing and attestation.
                       DESC
  s.homepage         = 'https://github.com/arrorLabArts/auroprint-flutter'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'ArrorLabArts' => 'info@arrorlabarts.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform         = :ios, '12.0'
  s.swift_version    = '5.0'
end
