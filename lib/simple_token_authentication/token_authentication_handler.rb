require 'active_support/concern'
require 'devise'

require 'simple_token_authentication/entities_manager'
require 'simple_token_authentication/devise_fallback_handler'
require 'simple_token_authentication/exception_fallback_handler'
require 'simple_token_authentication/sign_in_handler'
require 'simple_token_authentication/token_comparator'
require 'simple_token_authentication/entity'

module SimpleTokenAuthentication
  module TokenAuthenticationHandler
    extend ::ActiveSupport::Concern

    included do
      class_attribute :token_auth_entities
      token_auth_entities = {}
    end

    module InstanceMethods
      # This method is a hook and is meant to be overridden.
      #
      # It is not expected to return anything special,
      # only its side effects will be used.
      def after_successful_token_authentication
        # intentionally left blank
      end

      def handle_token_auth!(model)
        handle_token_auth(model)
        token_auth_fallback(model)
      end

      private

      def token_auth_fallback(model)
        self.class.token_auth_entities[model]&.handle!(self)
      end

      def handle_token_auth(model)
        entity = self.class.token_auth_entities[model]
        record = find_record_from_identifier(entity)

        return unless token_correct?(record, entity)

        perform_sign_in!(record)
        after_successful_token_authentication
      end

      def token_correct?(record, entity)
        TokenComparator.instance.compare(
          record.authentication_token,
          entity.get_token_from_params_or_headers(self)
        )
      end

      def perform_sign_in!(record)
        # Notice the store option defaults to false, so the record
        # identifier is not actually stored in the session and a token
        # is needed for every request. That behaviour can be configured
        # through the sign_in_token option.
        SignInHandler.instance.sign_in(self, record, store: SimpleTokenAuthentication.sign_in_token)
      end

      def find_record_from_identifier(entity)
        identifier_param_value = entity.get_identifier_from_params_or_headers(self).presence

        identifier_param_value = integrate_with_devise_case_insensitive_keys(identifier_param_value, entity)

        # The finder method should be compatible with all the model adapters,
        # namely ActiveRecord and Mongoid in all their supported versions.
        identifier_param_value && entity.model.find_for_authentication(entity.identifier => identifier_param_value)
      end

      # Private: Take benefit from Devise case-insensitive keys
      #
      # See https://github.com/plataformatec/devise/blob/v3.4.1/lib/generators/templates/devise.rb#L45-L48
      #
      # identifier_value - the original identifier_value String
      #
      # Returns an identifier String value which case follows the Devise case-insensitive keys policy
      def integrate_with_devise_case_insensitive_keys(identifier_value, entity)
        identifier_value.downcase! if identifier_value && Devise.case_insensitive_keys.include?(entity.identifier)
        identifier_value
      end
    end

    module ClassMethods
      def handle_token_authentication_for(model, options = {})
        token_auth_entities[model] ||= Entity.new(model, SimpleTokenAuthentication.parse_options(options))

        configure_fallback_handler_for(token_auth_entities[model])
        define_token_authentication_helpers_for(token_auth_entities[model].model)
        set_token_authentication_hooks_for(token_auth_entities[model])
      end

      private

      def configure_fallback_handler_for(entity)
        entity&.exception_handler = ExceptionFallbackHandler.instance
        entity&.devise_handler = DeviseFallbackHandler.instance
      end

      def define_token_authentication_helpers_for(model)
        define_method(token_auth_entities[model].auth_method) { handle_token_auth(model) }
        define_method(token_auth_entities[model].auth_bang_method) { handle_token_auth!(model) }
      end

      def set_token_authentication_hooks_for(entity)
        # See https://github.com/rails/rails/commit/9d62e04838f01f5589fa50b0baa480d60c815e2c
        if respond_to?(:before_action)
          before_action(entity.controller_auth_method, entity.controller_options)
        else
          before_filter(entity.controller_auth_method, entity.controller_options)
        end
      end
    end
  end
end
