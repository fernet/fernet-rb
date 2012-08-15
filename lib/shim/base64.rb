Base64.class_eval do
  def strict_encode64(bin)
    encode64(bin).tr("\n",'')
  end

  def strict_decode64(str)
    unless str.include?("\n")
      decode64(str)
    else
      raise(ArgumentError,"invalid base64")
    end
  end

  def urlsafe_encode64(bin)
    strict_encode64(bin).tr("+/", "-_")
  end

  def urlsafe_decode64(str)
    strict_decode64(str.tr("-_", "+/"))
  end
end
