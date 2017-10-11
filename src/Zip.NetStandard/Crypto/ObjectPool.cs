using System;
using System.Collections.Concurrent;

namespace Zip.NetStandard.Crypto
{
    internal interface IObjectPool<T>
    {
        T GetObject();
        void PutObject(T item);
    }

    internal abstract class ObjectPool
    {
        public PoolingPolicy Policy { get; }

        protected ObjectPool(PoolingPolicy policy)
        {
            Policy = policy;
        }

        public static ObjectPool<T> GetObjectPool<T>(Func<T> objectGenerator, PoolingPolicy policy)
        {
            switch (policy)
            {
                case PoolingPolicy.Reuse:
                {
                    return new ReusingObjectPool<T>(objectGenerator);
                }
                case PoolingPolicy.AlwaysCreate:
                {
                    return new AlwaysCreatingObjectPool<T>(objectGenerator);
                }
                case PoolingPolicy.SingleInstance:
                {
                    return new SingleInstanceObjectPool<T>(objectGenerator);
                }
            }
            throw new ArgumentOutOfRangeException(nameof(policy));
        }
    }

    internal abstract class ObjectPool<T> : ObjectPool, IObjectPool<T>
    {
        protected Func<T> ObjectGenerator { get; }

        protected ObjectPool(Func<T> objectGenerator, PoolingPolicy policy) : base(policy)
        {
            if (objectGenerator == null) throw new ArgumentNullException(nameof(objectGenerator));
            ObjectGenerator = objectGenerator;
        }

        public abstract T GetObject();
        public abstract void PutObject(T item);
    }

    internal enum PoolingPolicy
    {
        /// <summary>
        /// "Normal" pool policy that reuses recycled objects and creates new objects when empty
        /// </summary>
        Reuse,
        /// <summary>
        /// Always create new object
        /// </summary>
        AlwaysCreate,
        /// <summary>
        /// Create one object and always use it
        /// </summary>
        SingleInstance
    }

    internal class ReusingObjectPool<T> : ObjectPool<T>
    {
        private readonly ConcurrentBag<T> _objects;

        public ReusingObjectPool(Func<T> objectGenerator) : base(objectGenerator, PoolingPolicy.Reuse)
        {
            _objects = new ConcurrentBag<T>();
        }

        public override T GetObject()
        {
            T item;
            if (_objects.TryTake(out item)) return item;
            return ObjectGenerator();
        }

        public override void PutObject(T item)
        {
            _objects.Add(item);
        }
    }

    internal class AlwaysCreatingObjectPool<T> : ObjectPool<T>
    {
        public AlwaysCreatingObjectPool(Func<T> objectGenerator) : base(objectGenerator, PoolingPolicy.AlwaysCreate)
        {
        }

        public override T GetObject()
        {
            return ObjectGenerator();
        }

        public override void PutObject(T item)
        {
            if (item is IDisposable)
            {
                (item as IDisposable).Dispose();
            }
        }
    }

    internal class SingleInstanceObjectPool<T> : ObjectPool<T>
    {
        private readonly T _instance;

        public SingleInstanceObjectPool(Func<T> objectGenerator) : base(objectGenerator, PoolingPolicy.SingleInstance)
        {
            _instance = objectGenerator();
        }

        public override T GetObject()
        {
            return _instance;
        }

        public override void PutObject(T item)
        {
        }
    }


}
