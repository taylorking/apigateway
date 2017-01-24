return function (token) 
  if not (token == 'test') then
    return nil
  else 
    return { 
      email = 'test', 
      expires = 1400
    }
  end
end
