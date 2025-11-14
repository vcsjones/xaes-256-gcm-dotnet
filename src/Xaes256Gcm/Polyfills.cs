#if !NET
#pragma warning disable IDE0130
namespace System
{
    using System.Runtime.CompilerServices;

    internal static class Polyfills {
        extension(ObjectDisposedException) {
            public static void ThrowIf(bool condition, object instance) {
                if (condition) {
                    throw new ObjectDisposedException(instance?.GetType().FullName);
                }
            }

            public static void ThrowIf(bool condition, Type type) {
                if (condition) {
                    throw new ObjectDisposedException(type?.FullName);
                }
            }
        }

        extension (ArgumentNullException) {
            public static void ThrowIfNull(object? argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null) {
                if (argument is null) {
                    throw new ArgumentNullException(paramName);
                }
            }
        }
    }
}

namespace System.Runtime.CompilerServices
{
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
    internal sealed class CallerArgumentExpressionAttribute : Attribute
    {
        public CallerArgumentExpressionAttribute(string parameterName)
        {
            ParameterName = parameterName;
        }

        public string ParameterName { get; }
    }
}

#endif
