module SimpleTokenAuthentication
  class Entity
    attr_accessor :exception_handler, :devise_handler

    def initialize(model, options = {})
      @model = model.to_s.classify.constantize
      @name = @model.name
      @options = options.symbolize_keys
    end

    def name
      @name
    end

    def auth_method
      "authenticate_#{name_underscore}_from_token".to_sym
    end

    def auth_bang_method
      "#{auth_method}!".to_sym
    end

    def auth_object_method
      "current_#{name_underscore}".to_sym
    end

    def controller_auth_method
      no_fallback? ? auth_method : auth_object_method
    end

    def controller_options
      @options.slice(:only, :except, :if, :unless)
    end

    def name_underscore
      @name_underscore ||= @options.fetch(:as, @name).to_s.underscore.to_sym
    end

    def handle_fallback!(controller)
      fallback_handler&.fallback!(controller, self)
    end

    private

    # Return [String]
    # the name of the header to watch for the token authentication param
    def token_header_name
      SimpleTokenAuthentication.header_names.dig(name_underscore, :authentication_token) || "X-#{@model}-Token"
    end

    # Return [String]
    # the name of the header to watch for the email param
    def identifier_header_name
      SimpleTokenAuthentication.header_names.dig(name_underscore, identifier) || "X-#{@model}-#{identifier.to_s.camelize}"
    end

    # Return [String]
    # token param name
    def token_param_name
      "#{name_underscore}_token".to_sym
    end

    # Return [String]
    # identifier param name
    def identifier_param_name
      @identifier_param_name ||= "#{name_underscore}_#{identifier}".to_sym
    end

    # Return [String]
    # identifier key
    def identifier
      @identifier ||= SimpleTokenAuthentication.identifiers.fetch(name_underscore, :email)
    end

    # Return [@param | @header]
    # token;
    def get_token_from_params_or_headers(controller)
      controller.params.fetch(token_param_name, controller.request.headers[token_header_name])
    end

    # Return [@param | @header]
    # identifier
    def get_identifier_from_params_or_headers(controller)
      controller.params.fetch(identifier_param_name, controller.request.headers[identifier_header_name])
    end

    # Return [@exception_handler | @devise_handler | nil]
    # fallback handler object
    def fallback_handler
      case @options[:fallback]
      when :exception
        exception_handler
      when :devise
        devise_handler
      else
        nil
      end
    end
  end
end
