module SimpleTokenAuthentication
  class ExceptionFallbackHandler
    include Singleton

    # Notifies the failure of authentication to Warden in the same Devise does.
    # Does result in an HTTP 401 response in a Devise context.
    def fallback!(controller, entity)
      return unless controller.send(entity.auth_object_method).nil?

      throw(:warden, scope: entity.name_underscore)
    end
  end
end
